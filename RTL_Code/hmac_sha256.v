`timescale 1ns / 1ps
//=============================================================================
// HMAC-SHA-256 Implementation (RFC 2104)
// Accepts a 256-bit key and up to 264 bits of message
// HMAC(K,M) = SHA-256((K XOR opad) || SHA-256((K XOR ipad) || M))
// Processes exactly 4 SHA-256 blocks: 2 for inner hash, 2 for outer hash
//=============================================================================
module hmac_sha256 (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] key,        // 256-bit HMAC key
    input  wire [263:0] message,    // Up to 264 bits of message (MSB-aligned)
    input  wire [8:0]   msg_len,    // Message length in bits: 8, 256, or 264
    output reg  [255:0] mac,        // 256-bit HMAC result
    output reg          done        // Pulses high for 1 cycle when complete
);

    //=========================================================================
    // SHA-256 Instance (shared for all 4 blocks)
    //=========================================================================
    reg          sha_start;
    reg  [511:0] sha_block;
    reg  [255:0] sha_hash_in;
    reg          sha_use_prev;
    wire [255:0] sha_digest;
    wire         sha_done;

    sha256 sha_inst (
        .clk           (clk),
        .rst_n         (rst_n),
        .start         (sha_start),
        .block_in      (sha_block),
        .hash_in       (sha_hash_in),
        .use_prev_hash (sha_use_prev),
        .digest        (sha_digest),
        .done          (sha_done)
    );

    //=========================================================================
    // HMAC Padding Constants
    //=========================================================================
    localparam [511:0] IPAD_512 = {64{8'h36}}; // 0x3636...36 (64 bytes)
    localparam [511:0] OPAD_512 = {64{8'h5c}}; // 0x5c5c...5c (64 bytes)

    //=========================================================================
    // State Machine
    //=========================================================================
    localparam S_IDLE     = 4'd0,
               S_PREP     = 4'd1,
               S_INNER_B1 = 4'd2,  // Start SHA on K_ipad (block 1)
               S_WAIT_IB1 = 4'd3,  // Wait for block 1 hash
               S_INNER_B2 = 4'd4,  // Start SHA on padded message (block 2)
               S_WAIT_IB2 = 4'd5,  // Wait for inner hash
               S_OUTER_B1 = 4'd6,  // Start SHA on K_opad (block 1)
               S_WAIT_OB1 = 4'd7,  // Wait for block 1 hash
               S_OUTER_B2 = 4'd8,  // Start SHA on padded inner_hash (block 2)
               S_WAIT_OB2 = 4'd9;  // Wait for HMAC result

    reg [3:0] state;

    //=========================================================================
    // Internal Registers
    //=========================================================================
    reg [511:0] k_ipad;     // Key XOR ipad (512 bits)
    reg [511:0] k_opad;     // Key XOR opad (512 bits)
    reg [511:0] inner_b2;   // Inner hash block 2 (message + SHA padding)
    reg [511:0] outer_b2;   // Outer hash block 2 (inner_hash + SHA padding)

    //=========================================================================
    // Main FSM
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            done      <= 1'b0;
            mac       <= 256'd0;
            sha_start <= 1'b0;
        end else begin
            sha_start <= 1'b0; // Default: deassert start pulse

            case (state)
                //-------------------------------------------------------------
                S_IDLE: begin
                    done <= 1'b0;
                    if (start) state <= S_PREP;
                end

                //-------------------------------------------------------------
                // PREP: Compute K_ipad, K_opad, and construct inner block 2
                //-------------------------------------------------------------
                S_PREP: begin
                    // Pad key to 512 bits: key || zeros(256)
                    // Then XOR with ipad/opad
                    k_ipad <= {key, 256'd0} ^ IPAD_512;
                    k_opad <= {key, 256'd0} ^ OPAD_512;

                    // Construct inner block 2 with SHA-256 padding
                    // Format: message_bits || 0x80 || zero_padding || length_64bit_BE
                    // Total inner data length = 512 (K_ipad) + msg_len
                    case (msg_len)
                        9'd8: begin
                            // 1-byte message (e.g., counter byte 0x01)
                            // Block 2: msg[7:0] || 0x80 || zeros(432) || len(64)
                            inner_b2 <= {message[263:256], 8'h80, 432'd0, 64'd520};
                        end
                        9'd256: begin
                            // 32-byte message (e.g., IKM)
                            // Block 2: msg[255:0] || 0x80 || zeros(184) || len(64)
                            inner_b2 <= {message[263:8], 8'h80, 184'd0, 64'd768};
                        end
                        9'd264: begin
                            // 33-byte message (e.g., T1 || counter_byte)
                            // Block 2: msg[263:0] || 0x80 || zeros(176) || len(64)
                            inner_b2 <= {message[263:0], 8'h80, 176'd0, 64'd776};
                        end
                        default: begin
                            // Fallback: treat as 256-bit message
                            inner_b2 <= {message[263:8], 8'h80, 184'd0, 64'd768};
                        end
                    endcase
                    state <= S_INNER_B1;
                end

                //-------------------------------------------------------------
                // INNER HASH Block 1: SHA-256(K_ipad) using standard IV
                //-------------------------------------------------------------
                S_INNER_B1: begin
                    sha_block    <= k_ipad;
                    sha_hash_in  <= 256'd0;
                    sha_use_prev <= 1'b0;  // Use standard IV
                    sha_start    <= 1'b1;
                    state        <= S_WAIT_IB1;
                end

                S_WAIT_IB1: begin
                    if (sha_done) state <= S_INNER_B2;
                end

                //-------------------------------------------------------------
                // INNER HASH Block 2: SHA-256(msg_padded) chained from Block 1
                //-------------------------------------------------------------
                S_INNER_B2: begin
                    sha_block    <= inner_b2;
                    sha_hash_in  <= sha_digest;  // Chain from Block 1 result
                    sha_use_prev <= 1'b1;
                    sha_start    <= 1'b1;
                    state        <= S_WAIT_IB2;
                end

                S_WAIT_IB2: begin
                    if (sha_done) begin
                        // Inner hash complete; construct outer block 2
                        // Format: inner_hash(256) || 0x80 || zeros(184) || 768_as_64bit
                        outer_b2 <= {sha_digest, 8'h80, 184'd0, 64'd768};
                        state    <= S_OUTER_B1;
                    end
                end

                //-------------------------------------------------------------
                // OUTER HASH Block 1: SHA-256(K_opad) using standard IV
                //-------------------------------------------------------------
                S_OUTER_B1: begin
                    sha_block    <= k_opad;
                    sha_hash_in  <= 256'd0;
                    sha_use_prev <= 1'b0;  // Use standard IV
                    sha_start    <= 1'b1;
                    state        <= S_WAIT_OB1;
                end

                S_WAIT_OB1: begin
                    if (sha_done) state <= S_OUTER_B2;
                end

                //-------------------------------------------------------------
                // OUTER HASH Block 2: SHA-256(inner_hash_padded) chained
                //-------------------------------------------------------------
                S_OUTER_B2: begin
                    sha_block    <= outer_b2;
                    sha_hash_in  <= sha_digest;  // Chain from outer Block 1
                    sha_use_prev <= 1'b1;
                    sha_start    <= 1'b1;
                    state        <= S_WAIT_OB2;
                end

                S_WAIT_OB2: begin
                    if (sha_done) begin
                        mac   <= sha_digest;  // HMAC result
                        done  <= 1'b1;
                        state <= S_IDLE;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
