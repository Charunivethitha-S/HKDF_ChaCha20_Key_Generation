`timescale 1ns / 1ps
//=============================================================================
// ChaCha20 Quarter Round Function (RFC 7539, Section 2.1)
// Pure combinational ARX (Add-Rotate-XOR) operations
// a += b; d ^= a; d <<<= 16;
// c += d; b ^= c; b <<<= 12;
// a += b; d ^= a; d <<<= 8;
// c += d; b ^= c; b <<<= 7;
//=============================================================================
module chacha20_qr (
    input  wire [31:0] a_in, b_in, c_in, d_in,
    output wire [31:0] a_out, b_out, c_out, d_out
);

    // Step 1: a += b; d ^= a; d <<<= 16
    wire [31:0] a1, d1_xor, d1;
    assign a1     = a_in + b_in;
    assign d1_xor = d_in ^ a1;
    assign d1     = {d1_xor[15:0], d1_xor[31:16]}; // ROTL 16

    // Step 2: c += d; b ^= c; b <<<= 12
    wire [31:0] c2, b2_xor, b2;
    assign c2     = c_in + d1;
    assign b2_xor = b_in ^ c2;
    assign b2     = {b2_xor[19:0], b2_xor[31:20]}; // ROTL 12

    // Step 3: a += b; d ^= a; d <<<= 8
    wire [31:0] a3, d3_xor, d3;
    assign a3     = a1 + b2;
    assign d3_xor = d1 ^ a3;
    assign d3     = {d3_xor[23:0], d3_xor[31:24]}; // ROTL 8

    // Step 4: c += d; b ^= c; b <<<= 7
    wire [31:0] c4, b4_xor, b4;
    assign c4     = c2 + d3;
    assign b4_xor = b2 ^ c4;
    assign b4     = {b4_xor[24:0], b4_xor[31:25]}; // ROTL 7

    // Final outputs
    assign a_out = a3;
    assign b_out = b4;
    assign c_out = c4;
    assign d_out = d3;

endmodule
