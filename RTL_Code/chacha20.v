`timescale 1ns / 1ps
//=============================================================================
// ChaCha20 Stream Cipher Core (RFC 7539)
// Generates a 512-bit keystream block per invocation
// Processing: 10 double rounds (column+diagonal per cycle) = 10 cycles
// Key/Nonce are treated as big-endian byte streams; byte-swapped to LE words
//=============================================================================
module chacha20 (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] key,        // 256-bit key (big-endian byte order)
    input  wire [95:0]  nonce,      // 96-bit nonce (big-endian byte order)
    input  wire [31:0]  counter,    // 32-bit block counter
    output reg  [511:0] keystream,  // 512-bit keystream output (serialized LE)
    output reg          valid       // Pulses high for 1 cycle when block ready
);

    //=========================================================================
    // ChaCha20 Constants: ASCII for "expand 32-byte k" in little-endian words
    //=========================================================================
    localparam [31:0] C0 = 32'h61707865, // "expa"
                      C1 = 32'h3320646e, // "nd 3"
                      C2 = 32'h79622d32, // "2-by"
                      C3 = 32'h6b206574; // "te k"

    //=========================================================================
    // State Machine
    //=========================================================================
    localparam S_IDLE  = 2'd0,
               S_INIT  = 2'd1,
               S_ROUND = 2'd2,
               S_FINAL = 2'd3;

    reg [1:0] state;
    reg [3:0] round_cnt; // 0 to 9 (10 double rounds = 20 total rounds)

    //=========================================================================
    // State registers: 16 x 32-bit words
    //=========================================================================
    reg [31:0] s [0:15];       // Working state (modified during rounds)
    reg [31:0] s_init [0:15];  // Initial state (saved for final addition)

    //=========================================================================
    // Byte-swap function: converts big-endian 32-bit word to little-endian
    //=========================================================================
    function [31:0] bswap;
        input [31:0] w;
        bswap = {w[7:0], w[15:8], w[23:16], w[31:24]};
    endfunction

    //=========================================================================
    // Quarter Round Instances
    // Column round: QR(0,4,8,12), QR(1,5,9,13), QR(2,6,10,14), QR(3,7,11,15)
    // Diagonal round: QR(0,5,10,15), QR(1,6,11,12), QR(2,7,8,13), QR(3,4,9,14)
    //=========================================================================

    // Column round outputs
    wire [31:0] c0_a, c0_b, c0_c, c0_d;
    wire [31:0] c1_a, c1_b, c1_c, c1_d;
    wire [31:0] c2_a, c2_b, c2_c, c2_d;
    wire [31:0] c3_a, c3_b, c3_c, c3_d;

    chacha20_qr col0 (.a_in(s[ 0]), .b_in(s[ 4]), .c_in(s[ 8]), .d_in(s[12]),
                      .a_out(c0_a), .b_out(c0_b), .c_out(c0_c), .d_out(c0_d));
    chacha20_qr col1 (.a_in(s[ 1]), .b_in(s[ 5]), .c_in(s[ 9]), .d_in(s[13]),
                      .a_out(c1_a), .b_out(c1_b), .c_out(c1_c), .d_out(c1_d));
    chacha20_qr col2 (.a_in(s[ 2]), .b_in(s[ 6]), .c_in(s[10]), .d_in(s[14]),
                      .a_out(c2_a), .b_out(c2_b), .c_out(c2_c), .d_out(c2_d));
    chacha20_qr col3 (.a_in(s[ 3]), .b_in(s[ 7]), .c_in(s[11]), .d_in(s[15]),
                      .a_out(c3_a), .b_out(c3_b), .c_out(c3_c), .d_out(c3_d));

    // Diagonal round outputs (inputs come from column round outputs)
    // Diagonal 0: QR(s'[0], s'[5], s'[10], s'[15]) = QR(c0_a, c1_b, c2_c, c3_d)
    // Diagonal 1: QR(s'[1], s'[6], s'[11], s'[12]) = QR(c1_a, c2_b, c3_c, c0_d)
    // Diagonal 2: QR(s'[2], s'[7], s'[8],  s'[13]) = QR(c2_a, c3_b, c0_c, c1_d)
    // Diagonal 3: QR(s'[3], s'[4], s'[9],  s'[14]) = QR(c3_a, c0_b, c1_c, c2_d)
    wire [31:0] d0_a, d0_b, d0_c, d0_d;
    wire [31:0] d1_a, d1_b, d1_c, d1_d;
    wire [31:0] d2_a, d2_b, d2_c, d2_d;
    wire [31:0] d3_a, d3_b, d3_c, d3_d;

    chacha20_qr diag0 (.a_in(c0_a), .b_in(c1_b), .c_in(c2_c), .d_in(c3_d),
                       .a_out(d0_a), .b_out(d0_b), .c_out(d0_c), .d_out(d0_d));
    chacha20_qr diag1 (.a_in(c1_a), .b_in(c2_b), .c_in(c3_c), .d_in(c0_d),
                       .a_out(d1_a), .b_out(d1_b), .c_out(d1_c), .d_out(d1_d));
    chacha20_qr diag2 (.a_in(c2_a), .b_in(c3_b), .c_in(c0_c), .d_in(c1_d),
                       .a_out(d2_a), .b_out(d2_b), .c_out(d2_c), .d_out(d2_d));
    chacha20_qr diag3 (.a_in(c3_a), .b_in(c0_b), .c_in(c1_c), .d_in(c2_d),
                       .a_out(d3_a), .b_out(d3_b), .c_out(d3_c), .d_out(d3_d));

    //=========================================================================
    // Loop variable
    //=========================================================================
    integer i;

    //=========================================================================
    // Main FSM
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            valid     <= 1'b0;
            keystream <= 512'd0;
            round_cnt <= 4'd0;
        end else begin
            valid <= 1'b0; // Default: deassert valid

            case (state)
                //-------------------------------------------------------------
                // IDLE: Wait for start
                //-------------------------------------------------------------
                S_IDLE: begin
                    if (start) state <= S_INIT;
                end

                //-------------------------------------------------------------
                // INIT: Set up the 4x4 state matrix
                // [C0  C1  C2  C3 ]  <- Constants
                // [K0  K1  K2  K3 ]  <- Key words (byte-swapped to LE)
                // [K4  K5  K6  K7 ]
                // [CTR N0  N1  N2 ]  <- Counter + Nonce words
                //-------------------------------------------------------------
                S_INIT: begin
                    // Constants (already in LE format)
                    s[0]  <= C0;  s[1]  <= C1;  s[2]  <= C2;  s[3]  <= C3;

                    // Key: byte-swap each 32-bit chunk from big-endian input
                    s[4]  <= bswap(key[255:224]); s[5]  <= bswap(key[223:192]);
                    s[6]  <= bswap(key[191:160]); s[7]  <= bswap(key[159:128]);
                    s[8]  <= bswap(key[127:96]);  s[9]  <= bswap(key[95:64]);
                    s[10] <= bswap(key[63:32]);   s[11] <= bswap(key[31:0]);

                    // Counter (loaded as-is, it's a number not a byte string)
                    s[12] <= counter;

                    // Nonce: byte-swap each 32-bit chunk
                    s[13] <= bswap(nonce[95:64]);
                    s[14] <= bswap(nonce[63:32]);
                    s[15] <= bswap(nonce[31:0]);

                    // Save initial state for final addition
                    s_init[0]  <= C0;  s_init[1]  <= C1;
                    s_init[2]  <= C2;  s_init[3]  <= C3;
                    s_init[4]  <= bswap(key[255:224]); s_init[5]  <= bswap(key[223:192]);
                    s_init[6]  <= bswap(key[191:160]); s_init[7]  <= bswap(key[159:128]);
                    s_init[8]  <= bswap(key[127:96]);  s_init[9]  <= bswap(key[95:64]);
                    s_init[10] <= bswap(key[63:32]);   s_init[11] <= bswap(key[31:0]);
                    s_init[12] <= counter;
                    s_init[13] <= bswap(nonce[95:64]);
                    s_init[14] <= bswap(nonce[63:32]);
                    s_init[15] <= bswap(nonce[31:0]);

                    round_cnt <= 4'd0;
                    state     <= S_ROUND;
                end

                //-------------------------------------------------------------
                // ROUND: Execute 1 double round per cycle (10 iterations total)
                // Each double round = column QR + diagonal QR (combinational)
                //-------------------------------------------------------------
                S_ROUND: begin
                    // Update state from double round outputs
                    // Map diagonal outputs back to the correct state indices:
                    // d0 operates on positions (0,5,10,15)
                    // d1 operates on positions (1,6,11,12)
                    // d2 operates on positions (2,7,8,13)
                    // d3 operates on positions (3,4,9,14)
                    s[0]  <= d0_a;  s[1]  <= d1_a;  s[2]  <= d2_a;  s[3]  <= d3_a;
                    s[4]  <= d3_b;  s[5]  <= d0_b;  s[6]  <= d1_b;  s[7]  <= d2_b;
                    s[8]  <= d2_c;  s[9]  <= d3_c;  s[10] <= d0_c;  s[11] <= d1_c;
                    s[12] <= d1_d;  s[13] <= d2_d;  s[14] <= d3_d;  s[15] <= d0_d;

                    if (round_cnt == 4'd9)
                        state <= S_FINAL;
                    else
                        round_cnt <= round_cnt + 4'd1;
                end

                //-------------------------------------------------------------
                // FINAL: Add initial state to final state, then serialize
                // Each word is byte-swapped back to LE byte order for output
                //-------------------------------------------------------------
                S_FINAL: begin
                    keystream <= {
                        bswap(s[0]  + s_init[0]),  bswap(s[1]  + s_init[1]),
                        bswap(s[2]  + s_init[2]),  bswap(s[3]  + s_init[3]),
                        bswap(s[4]  + s_init[4]),  bswap(s[5]  + s_init[5]),
                        bswap(s[6]  + s_init[6]),  bswap(s[7]  + s_init[7]),
                        bswap(s[8]  + s_init[8]),  bswap(s[9]  + s_init[9]),
                        bswap(s[10] + s_init[10]), bswap(s[11] + s_init[11]),
                        bswap(s[12] + s_init[12]), bswap(s[13] + s_init[13]),
                        bswap(s[14] + s_init[14]), bswap(s[15] + s_init[15])
                    };
                    valid <= 1'b1;
                    state <= S_IDLE;
                end
            endcase
        end
    end

endmodule
