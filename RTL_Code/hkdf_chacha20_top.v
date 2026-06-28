`timescale 1ns / 1ps
//=============================================================================
// HKDF-ChaCha20 Top-Level Module
// Integrates HKDF key derivation with ChaCha20 keystream generation
//
// Operation:
//   1. Assert 'start' → runs HKDF to derive key+nonce from IKM/Salt
//   2. Automatically generates first 512-bit keystream block (counter=0)
//   3. Assert 'next_block' → increments counter and generates next block
//   4. Repeat step 3 for as many blocks as needed
//=============================================================================
module hkdf_chacha20_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,        // Trigger full HKDF + first block
    input  wire         next_block,   // Trigger next keystream block
    input  wire [255:0] ikm,          // Input Keying Material
    input  wire [255:0] salt,         // Salt for HKDF
    output wire [511:0] keystream,    // 512-bit keystream block output
    output wire         valid,        // Pulses high when keystream block ready
    output reg          hkdf_done,    // Goes high after HKDF completes
    output reg  [31:0]  block_count   // Number of blocks generated so far
);

    //=========================================================================
    // HKDF Instance
    //=========================================================================
    reg          hkdf_start;
    wire [255:0] hkdf_key;
    wire [95:0]  hkdf_nonce;
    wire         hkdf_done_w;

    hkdf hkdf_inst (
        .clk           (clk),
        .rst_n         (rst_n),
        .start         (hkdf_start),
        .ikm           (ikm),
        .salt          (salt),
        .derived_key   (hkdf_key),
        .derived_nonce (hkdf_nonce),
        .done          (hkdf_done_w)
    );

    //=========================================================================
    // ChaCha20 Instance
    //=========================================================================
    reg          cc_start;
    reg  [31:0]  cc_counter;

    chacha20 cc_inst (
        .clk      (clk),
        .rst_n    (rst_n),
        .start    (cc_start),
        .key      (hkdf_key),
        .nonce    (hkdf_nonce),
        .counter  (cc_counter),
        .keystream(keystream),
        .valid    (valid)
    );

    //=========================================================================
    // Top-Level State Machine
    //=========================================================================
    localparam S_IDLE      = 3'd0,
               S_HKDF      = 3'd1,  // Trigger HKDF
               S_WAIT_HKDF = 3'd2,  // Wait for HKDF completion
               S_CC_GEN    = 3'd3,  // Trigger ChaCha20 block generation
               S_WAIT_CC   = 3'd4,  // Wait for keystream block
               S_READY     = 3'd5;  // Block ready, wait for next_block

    reg [2:0] state;

    //=========================================================================
    // Main FSM
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state       <= S_IDLE;
            hkdf_start  <= 1'b0;
            cc_start    <= 1'b0;
            cc_counter  <= 32'd0;
            block_count <= 32'd0;
            hkdf_done   <= 1'b0;
        end else begin
            hkdf_start <= 1'b0; // Default pulses
            cc_start   <= 1'b0;

            case (state)
                //-------------------------------------------------------------
                S_IDLE: begin
                    hkdf_done <= 1'b0;
                    if (start) begin
                        cc_counter  <= 32'd0;
                        block_count <= 32'd0;
                        state       <= S_HKDF;
                    end
                end

                //-------------------------------------------------------------
                // Trigger HKDF key derivation
                //-------------------------------------------------------------
                S_HKDF: begin
                    hkdf_start <= 1'b1;
                    state      <= S_WAIT_HKDF;
                end

                //-------------------------------------------------------------
                // Wait for HKDF to produce derived key + nonce
                //-------------------------------------------------------------
                S_WAIT_HKDF: begin
                    if (hkdf_done_w) begin
                        hkdf_done <= 1'b1;
                        state     <= S_CC_GEN;
                    end
                end

                //-------------------------------------------------------------
                // Trigger ChaCha20 for current counter value
                //-------------------------------------------------------------
                S_CC_GEN: begin
                    cc_start <= 1'b1;
                    state    <= S_WAIT_CC;
                end

                //-------------------------------------------------------------
                // Wait for ChaCha20 to produce 512-bit keystream block
                //-------------------------------------------------------------
                S_WAIT_CC: begin
                    if (valid) begin
                        block_count <= block_count + 32'd1;
                        cc_counter  <= cc_counter + 32'd1;
                        state       <= S_READY;
                    end
                end

                //-------------------------------------------------------------
                // Block ready; wait for next_block to generate another
                //-------------------------------------------------------------
                S_READY: begin
                    if (next_block)
                        state <= S_CC_GEN;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
