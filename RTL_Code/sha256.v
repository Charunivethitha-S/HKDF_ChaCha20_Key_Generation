`timescale 1ns / 1ps
//=============================================================================
// SHA-256 Single-Block Hash Engine (FIPS 180-4)
// Supports chained multi-block hashing via use_prev_hash input
// Processing: 1 round per clock cycle = 67 cycles per block
//=============================================================================
module sha256 (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [511:0] block_in,      // 512-bit message block (big-endian words)
    input  wire [255:0] hash_in,       // Previous hash state for chaining
    input  wire         use_prev_hash, // 0 = use standard IV, 1 = chain from hash_in
    output reg  [255:0] digest,        // 256-bit hash output
    output reg          done           // Pulses high for 1 cycle when complete
);

    //=========================================================================
    // SHA-256 Initial Hash Values (FIPS 180-4, Section 5.3.3)
    //=========================================================================
    localparam [31:0] IV0 = 32'h6a09e667, IV1 = 32'hbb67ae85,
                      IV2 = 32'h3c6ef372, IV3 = 32'ha54ff53a,
                      IV4 = 32'h510e527f, IV5 = 32'h9b05688c,
                      IV6 = 32'h1f83d9ab, IV7 = 32'h5be0cd19;

    //=========================================================================
    // SHA-256 Round Constants K[0..63] (FIPS 180-4, Section 4.2.2)
    //=========================================================================
    reg [31:0] K_ROM [0:63];
    initial begin
        K_ROM[ 0] = 32'h428a2f98; K_ROM[ 1] = 32'h71374491;
        K_ROM[ 2] = 32'hb5c0fbcf; K_ROM[ 3] = 32'he9b5dba5;
        K_ROM[ 4] = 32'h3956c25b; K_ROM[ 5] = 32'h59f111f1;
        K_ROM[ 6] = 32'h923f82a4; K_ROM[ 7] = 32'hab1c5ed5;
        K_ROM[ 8] = 32'hd807aa98; K_ROM[ 9] = 32'h12835b01;
        K_ROM[10] = 32'h243185be; K_ROM[11] = 32'h550c7dc3;
        K_ROM[12] = 32'h72be5d74; K_ROM[13] = 32'h80deb1fe;
        K_ROM[14] = 32'h9bdc06a7; K_ROM[15] = 32'hc19bf174;
        K_ROM[16] = 32'he49b69c1; K_ROM[17] = 32'hefbe4786;
        K_ROM[18] = 32'h0fc19dc6; K_ROM[19] = 32'h240ca1cc;
        K_ROM[20] = 32'h2de92c6f; K_ROM[21] = 32'h4a7484aa;
        K_ROM[22] = 32'h5cb0a9dc; K_ROM[23] = 32'h76f988da;
        K_ROM[24] = 32'h983e5152; K_ROM[25] = 32'ha831c66d;
        K_ROM[26] = 32'hb00327c8; K_ROM[27] = 32'hbf597fc7;
        K_ROM[28] = 32'hc6e00bf3; K_ROM[29] = 32'hd5a79147;
        K_ROM[30] = 32'h06ca6351; K_ROM[31] = 32'h14292967;
        K_ROM[32] = 32'h27b70a85; K_ROM[33] = 32'h2e1b2138;
        K_ROM[34] = 32'h4d2c6dfc; K_ROM[35] = 32'h53380d13;
        K_ROM[36] = 32'h650a7354; K_ROM[37] = 32'h766a0abb;
        K_ROM[38] = 32'h81c2c92e; K_ROM[39] = 32'h92722c85;
        K_ROM[40] = 32'ha2bfe8a1; K_ROM[41] = 32'ha81a664b;
        K_ROM[42] = 32'hc24b8b70; K_ROM[43] = 32'hc76c51a3;
        K_ROM[44] = 32'hd192e819; K_ROM[45] = 32'hd6990624;
        K_ROM[46] = 32'hf40e3585; K_ROM[47] = 32'h106aa070;
        K_ROM[48] = 32'h19a4c116; K_ROM[49] = 32'h1e376c08;
        K_ROM[50] = 32'h2748774c; K_ROM[51] = 32'h34b0bcb5;
        K_ROM[52] = 32'h391c0cb3; K_ROM[53] = 32'h4ed8aa4a;
        K_ROM[54] = 32'h5b9cca4f; K_ROM[55] = 32'h682e6ff3;
        K_ROM[56] = 32'h748f82ee; K_ROM[57] = 32'h78a5636f;
        K_ROM[58] = 32'h84c87814; K_ROM[59] = 32'h8cc70208;
        K_ROM[60] = 32'h90befffa; K_ROM[61] = 32'ha4506ceb;
        K_ROM[62] = 32'hbef9a3f7; K_ROM[63] = 32'hc67178f2;
    end

    //=========================================================================
    // State Machine
    //=========================================================================
    localparam S_IDLE    = 2'd0,
               S_INIT    = 2'd1,
               S_PROCESS = 2'd2,
               S_FINISH  = 2'd3;

    reg [1:0]  state;
    reg [6:0]  round_cnt; // 0 to 63

    //=========================================================================
    // Hash state registers and working variables
    //=========================================================================
    reg [31:0] H0, H1, H2, H3, H4, H5, H6, H7;
    reg [31:0] va, vb, vc, vd, ve, vf, vg, vh;
    reg [31:0] W [0:63]; // Message schedule array

    //=========================================================================
    // SHA-256 Functions (Combinational)
    //=========================================================================
    function [31:0] Ch;
        input [31:0] x, y, z;
        Ch = (x & y) ^ (~x & z);
    endfunction

    function [31:0] Maj;
        input [31:0] x, y, z;
        Maj = (x & y) ^ (x & z) ^ (y & z);
    endfunction

    // Big Sigma functions (compression function)
    function [31:0] Sigma0; // ROTR(2) ^ ROTR(13) ^ ROTR(22)
        input [31:0] x;
        Sigma0 = {x[1:0], x[31:2]} ^ {x[12:0], x[31:13]} ^ {x[21:0], x[31:22]};
    endfunction

    function [31:0] Sigma1; // ROTR(6) ^ ROTR(11) ^ ROTR(25)
        input [31:0] x;
        Sigma1 = {x[5:0], x[31:6]} ^ {x[10:0], x[31:11]} ^ {x[24:0], x[31:25]};
    endfunction

    // Small sigma functions (message schedule)
    function [31:0] sigma0_f; // ROTR(7) ^ ROTR(18) ^ SHR(3)
        input [31:0] x;
        sigma0_f = {x[6:0], x[31:7]} ^ {x[17:0], x[31:18]} ^ (x >> 3);
    endfunction

    function [31:0] sigma1_f; // ROTR(17) ^ ROTR(19) ^ SHR(10)
        input [31:0] x;
        sigma1_f = {x[16:0], x[31:17]} ^ {x[18:0], x[31:19]} ^ (x >> 10);
    endfunction

    //=========================================================================
    // Temporary variables (blocking assignments for combinational intermediates)
    //=========================================================================
    reg [31:0] T1, T2, w_val;
    integer i;

    //=========================================================================
    // Main FSM
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            done      <= 1'b0;
            digest    <= 256'd0;
            round_cnt <= 7'd0;
        end else begin
            case (state)
                //-------------------------------------------------------------
                // IDLE: Wait for start pulse
                //-------------------------------------------------------------
                S_IDLE: begin
                    done <= 1'b0;
                    if (start) begin
                        // Load initial hash values (IV or chained)
                        if (use_prev_hash) begin
                            H0 <= hash_in[255:224]; H1 <= hash_in[223:192];
                            H2 <= hash_in[191:160]; H3 <= hash_in[159:128];
                            H4 <= hash_in[127:96];  H5 <= hash_in[95:64];
                            H6 <= hash_in[63:32];   H7 <= hash_in[31:0];
                        end else begin
                            H0 <= IV0; H1 <= IV1; H2 <= IV2; H3 <= IV3;
                            H4 <= IV4; H5 <= IV5; H6 <= IV6; H7 <= IV7;
                        end
                        // Parse message block into W[0..15] (big-endian 32-bit words)
                        for (i = 0; i < 16; i = i + 1)
                            W[i] <= block_in[511 - i*32 -: 32];
                        state <= S_INIT;
                    end
                end

                //-------------------------------------------------------------
                // INIT: Copy hash state to working variables
                //-------------------------------------------------------------
                S_INIT: begin
                    va <= H0; vb <= H1; vc <= H2; vd <= H3;
                    ve <= H4; vf <= H5; vg <= H6; vh <= H7;
                    round_cnt <= 7'd0;
                    state <= S_PROCESS;
                end

                //-------------------------------------------------------------
                // PROCESS: Execute 64 compression rounds (1 per clock cycle)
                //-------------------------------------------------------------
                S_PROCESS: begin
                    // Compute current W value
                    if (round_cnt < 7'd16)
                        w_val = W[round_cnt];
                    else begin
                        w_val = sigma1_f(W[round_cnt - 7'd2])  + W[round_cnt - 7'd7] +
                                sigma0_f(W[round_cnt - 7'd15]) + W[round_cnt - 7'd16];
                        W[round_cnt] <= w_val; // Store for future rounds
                    end

                    // Compression function
                    T1 = vh + Sigma1(ve) + Ch(ve, vf, vg) + K_ROM[round_cnt] + w_val;
                    T2 = Sigma0(va) + Maj(va, vb, vc);

                    vh <= vg;
                    vg <= vf;
                    vf <= ve;
                    ve <= vd + T1;
                    vd <= vc;
                    vc <= vb;
                    vb <= va;
                    va <= T1 + T2;

                    if (round_cnt == 7'd63)
                        state <= S_FINISH;
                    else
                        round_cnt <= round_cnt + 7'd1;
                end

                //-------------------------------------------------------------
                // FINISH: Compute final hash = initial_H + working_vars
                //-------------------------------------------------------------
                S_FINISH: begin
                    digest <= {H0 + va, H1 + vb, H2 + vc, H3 + vd,
                               H4 + ve, H5 + vf, H6 + vg, H7 + vh};
                    done   <= 1'b1;
                    state  <= S_IDLE;
                end
            endcase
        end
    end

endmodule
