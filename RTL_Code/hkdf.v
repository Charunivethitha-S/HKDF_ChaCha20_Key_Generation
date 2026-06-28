`timescale 1ns / 1ps
//=============================================================================
// HKDF Extract-then-Expand (RFC 5869) using HMAC-SHA-256
// Derives a 256-bit ChaCha20 key and 96-bit nonce from IKM + Salt
//
// Extract:   PRK = HMAC-SHA-256(Salt, IKM)
// Expand T1: T1  = HMAC-SHA-256(PRK, 0x01)           -> 32 bytes (Key)
// Expand T2: T2  = HMAC-SHA-256(PRK, T1 || 0x02)     -> first 12 bytes (Nonce)
//=============================================================================
module hkdf (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] ikm,            // Input Keying Material (256 bits)
    input  wire [255:0] salt,           // Salt value (256 bits)
    output reg  [255:0] derived_key,    // Derived ChaCha20 key (32 bytes)
    output reg  [95:0]  derived_nonce,  // Derived ChaCha20 nonce (12 bytes)
    output reg          done            // Pulses high for 1 cycle when complete
);

    //=========================================================================
    // HMAC-SHA-256 Instance (shared for all 3 HMAC operations)
    //=========================================================================
    reg          hmac_start;
    reg  [255:0] hmac_key;
    reg  [263:0] hmac_message;
    reg  [8:0]   hmac_msg_len;
    wire [255:0] hmac_mac;
    wire         hmac_done;

    hmac_sha256 hmac_inst (
        .clk     (clk),
        .rst_n   (rst_n),
        .start   (hmac_start),
        .key     (hmac_key),
        .message (hmac_message),
        .msg_len (hmac_msg_len),
        .mac     (hmac_mac),
        .done    (hmac_done)
    );

    //=========================================================================
    // State Machine
    //=========================================================================
    localparam S_IDLE      = 3'd0,
               S_EXTRACT   = 3'd1,  // Start HMAC(Salt, IKM)
               S_WAIT_EXT  = 3'd2,  // Wait for PRK
               S_EXPAND_T1 = 3'd3,  // Start HMAC(PRK, 0x01)
               S_WAIT_T1   = 3'd4,  // Wait for T1
               S_EXPAND_T2 = 3'd5,  // Start HMAC(PRK, T1||0x02)
               S_WAIT_T2   = 3'd6;  // Wait for T2

    reg [2:0] state;

    //=========================================================================
    // Internal Registers
    //=========================================================================
    reg [255:0] prk;  // Pseudorandom Key (extract output)
    reg [255:0] t1;   // First expansion block (becomes the derived key)

    //=========================================================================
    // Main FSM
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            done         <= 1'b0;
            hmac_start   <= 1'b0;
            derived_key  <= 256'd0;
            derived_nonce <= 96'd0;
        end else begin
            hmac_start <= 1'b0; // Default: deassert start pulse

            case (state)
                //-------------------------------------------------------------
                S_IDLE: begin
                    done <= 1'b0;
                    if (start) state <= S_EXTRACT;
                end

                //-------------------------------------------------------------
                // EXTRACT: PRK = HMAC-SHA-256(Salt, IKM)
                // Key = Salt (256 bits), Message = IKM (256 bits)
                //-------------------------------------------------------------
                S_EXTRACT: begin
                    hmac_key     <= salt;
                    hmac_message <= {ikm, 8'd0};  // IKM at [263:8], pad low byte
                    hmac_msg_len <= 9'd256;
                    hmac_start   <= 1'b1;
                    state        <= S_WAIT_EXT;
                end

                S_WAIT_EXT: begin
                    if (hmac_done) begin
                        prk   <= hmac_mac;  // Save PRK
                        state <= S_EXPAND_T1;
                    end
                end

                //-------------------------------------------------------------
                // EXPAND T1: T1 = HMAC-SHA-256(PRK, 0x01)
                // Key = PRK, Message = single byte 0x01
                //-------------------------------------------------------------
                S_EXPAND_T1: begin
                    hmac_key     <= prk;
                    hmac_message <= {8'h01, 256'd0};  // 0x01 at [263:256]
                    hmac_msg_len <= 9'd8;
                    hmac_start   <= 1'b1;
                    state        <= S_WAIT_T1;
                end

                S_WAIT_T1: begin
                    if (hmac_done) begin
                        t1    <= hmac_mac;  // Save T1 (becomes derived key)
                        state <= S_EXPAND_T2;
                    end
                end

                //-------------------------------------------------------------
                // EXPAND T2: T2 = HMAC-SHA-256(PRK, T1 || 0x02)
                // Key = PRK, Message = T1(256 bits) || 0x02(8 bits) = 264 bits
                //-------------------------------------------------------------
                S_EXPAND_T2: begin
                    hmac_key     <= prk;
                    hmac_message <= {t1, 8'h02};  // T1 at [263:8], 0x02 at [7:0]
                    hmac_msg_len <= 9'd264;
                    hmac_start   <= 1'b1;
                    state        <= S_WAIT_T2;
                end

                S_WAIT_T2: begin
                    if (hmac_done) begin
                        derived_key   <= t1;                  // OKM bytes 0-31 = Key
                        derived_nonce <= hmac_mac[255:160];    // OKM bytes 32-43 = Nonce
                        done          <= 1'b1;
                        state         <= S_IDLE;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
