`timescale 1ns / 1ps
//=============================================================================
// Testbench: HKDF-ChaCha20 Keystream Generator
//
// 1. Runs a ChaCha20 Known-Answer Test (KAT) against RFC 7539 test vector
// 2. Runs the full HKDF-ChaCha20 flow to generate 2000 blocks (1,024,000 bits)
// 3. Writes keystream to binary file (keystream_1M.bin) for NIST SP 800-22
// 4. Writes hex file (keystream_1M_hex.txt) for human-readable verification
//=============================================================================
module tb_hkdf_chacha20;

    //=========================================================================
    // Signals for the main HKDF-ChaCha20 top module
    //=========================================================================
    reg          clk;
    reg          rst_n;
    reg          start;
    reg          next_block;
    reg  [255:0] ikm;
    reg  [255:0] salt;
    wire [511:0] keystream;
    wire         valid;
    wire         hkdf_done;
    wire [31:0]  block_count;

    hkdf_chacha20_top uut (
        .clk         (clk),
        .rst_n       (rst_n),
        .start       (start),
        .next_block  (next_block),
        .ikm         (ikm),
        .salt        (salt),
        .keystream   (keystream),
        .valid       (valid),
        .hkdf_done   (hkdf_done),
        .block_count (block_count)
    );

    //=========================================================================
    // Standalone ChaCha20 instance for Known-Answer Test (RFC 7539 Sec 2.3.2)
    //=========================================================================
    reg          kat_start;
    wire [511:0] kat_keystream;
    wire         kat_valid;

    chacha20 kat_cc (
        .clk      (clk),
        .rst_n    (rst_n),
        .start    (kat_start),
        .key      (256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f),
        .nonce    (96'h000000090000004a00000000),
        .counter  (32'd1),
        .keystream(kat_keystream),
        .valid    (kat_valid)
    );

    //=========================================================================
    // Clock Generation: 100 MHz (10 ns period)
    //=========================================================================
    always #5 clk = ~clk;

    //=========================================================================
    // File handles and counters
    //=========================================================================
    integer fd_bin;
    integer fd_hex;
    integer total_blocks;
    integer j;
    reg [7:0] byte_val;

    localparam NUM_BLOCKS = 2000; // 2000 * 512 = 1,024,000 bits

    //=========================================================================
    // Expected KAT output (RFC 7539, Section 2.3.2)
    //=========================================================================
    localparam [511:0] KAT_EXPECTED = 512'h10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e;

    //=========================================================================
    // Task: Write one 512-bit block to both output files
    //=========================================================================
    task write_block;
        input [511:0] data;
        integer idx;
        begin
            // Write 64 bytes to binary file (MSB byte first)
            for (idx = 63; idx >= 0; idx = idx - 1) begin
                byte_val = data[idx*8 +: 8];
                $fwrite(fd_bin, "%c", byte_val);
            end
            // Write hex string to text file
            $fwrite(fd_hex, "%0128h\n", data);
        end
    endtask

    //=========================================================================
    // Main Test Sequence
    //=========================================================================
    initial begin
        // Initialize signals
        clk        = 1'b0;
        rst_n      = 1'b0;
        start      = 1'b0;
        next_block = 1'b0;
        kat_start  = 1'b0;

        // Test IKM and Salt values
        ikm  = 256'h0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;
        salt = 256'h606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f;

        // =====================================================================
        // PHASE 0: Reset
        // =====================================================================
        $display("");
        $display("============================================================");
        $display("  HKDF-ChaCha20 Keystream Generator — Vivado Testbench");
        $display("============================================================");
        #100;
        rst_n = 1'b1;
        @(posedge clk);
        @(posedge clk);
        $display("[RESET] System reset complete at time %0t ns", $time);

        // =====================================================================
        // PHASE 1: ChaCha20 Known-Answer Test (RFC 7539 Section 2.3.2)
        // =====================================================================
        $display("");
        $display("------------------------------------------------------------");
        $display("[KAT] Running ChaCha20 Known-Answer Test (RFC 7539)...");
        $display("------------------------------------------------------------");

        @(posedge clk);
        kat_start = 1'b1;
        @(posedge clk);
        kat_start = 1'b0;

        // Wait for KAT result
        @(posedge kat_valid);
        @(posedge clk); // Allow 1 cycle for output to settle

        if (kat_keystream == KAT_EXPECTED) begin
            $display("[KAT] PASSED — ChaCha20 output matches RFC 7539 test vector");
            $display("[KAT] Output: %h", kat_keystream);
        end else begin
            $display("[KAT] *** FAILED *** — ChaCha20 output does NOT match!");
            $display("[KAT] Expected: %h", KAT_EXPECTED);
            $display("[KAT] Got:      %h", kat_keystream);
            $display("[KAT] Aborting simulation due to KAT failure.");
            $finish;
        end

        // =====================================================================
        // PHASE 2: Full HKDF-ChaCha20 Keystream Generation (2000 blocks)
        // =====================================================================
        $display("");
        $display("------------------------------------------------------------");
        $display("[GEN] Starting HKDF key derivation...");
        $display("[GEN] IKM:  %h", ikm);
        $display("[GEN] Salt: %h", salt);
        $display("------------------------------------------------------------");

        // Open output files
        fd_bin = $fopen("keystream_1M.bin", "wb");
        fd_hex = $fopen("keystream_1M_hex.txt", "w");
        if (fd_bin == 0 || fd_hex == 0) begin
            $display("[ERROR] Could not open output files!");
            $finish;
        end

        // Trigger HKDF + first block generation
        @(posedge clk);
        start = 1'b1;
        @(posedge clk);
        start = 1'b0;

        // Wait for HKDF completion
        @(posedge hkdf_done);
        $display("[GEN] HKDF derivation complete at time %0t ns", $time);

        // Wait for first keystream block (counter = 0)
        @(posedge valid);
        write_block(keystream);
        total_blocks = 1;
        $display("[GEN] Block 0 generated: %h...", keystream[511:384]);

        // Generate remaining blocks
        while (total_blocks < NUM_BLOCKS) begin
            // Wait for top module to reach S_READY state
            @(posedge clk);
            @(posedge clk);

            // Request next block
            next_block = 1'b1;
            @(posedge clk);
            next_block = 1'b0;

            // Wait for keystream block
            @(posedge valid);
            write_block(keystream);
            total_blocks = total_blocks + 1;

            // Progress reporting
            if (total_blocks % 200 == 0)
                $display("[GEN] Progress: %0d / %0d blocks at time %0t ns",
                         total_blocks, NUM_BLOCKS, $time);
        end

        // Close files
        $fclose(fd_bin);
        $fclose(fd_hex);

        // =====================================================================
        // PHASE 3: Summary
        // =====================================================================
        $display("");
        $display("============================================================");
        $display("  GENERATION COMPLETE");
        $display("============================================================");
        $display("  Total Blocks Generated : %0d", total_blocks);
        $display("  Total Bits             : %0d", total_blocks * 512);
        $display("  Total Bytes            : %0d", total_blocks * 64);
        $display("  Binary Output File     : keystream_1M.bin");
        $display("  Hex Text Output File   : keystream_1M_hex.txt");
        $display("============================================================");
        $display("");
        $display("  Next Steps:");
        $display("  1. Verify keystream_1M.bin exists (%0d bytes)", total_blocks * 64);
        $display("  2. Run NIST SP 800-22 tests:");
        $display("       python run_nist_tests.py keystream_1M.bin");
        $display("============================================================");

        #200;
        $finish;
    end

    //=========================================================================
    // Timeout watchdog (prevent infinite simulation)
    //=========================================================================
    initial begin
        #500_000_000; // 500 ms timeout
        $display("[ERROR] Simulation timeout! Something may be stuck.");
        $finish;
    end

endmodule
