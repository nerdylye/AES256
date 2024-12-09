// Code your testbench here
// or browse Examples
`timescale 1ns/1ps

module aes_256_tb;

  // Declare inputs and outputs
  logic enable;
  logic reset;
  logic [127:0] plaintext;
  logic [255:0] key;
  logic [127:0] ciphertext;

  // Instantiate the AES-256 module
  aes_256 aes_dut (
    .enable(enable),
    .reset(reset),
    .plaintext(plaintext),
    .key(key),
    .ciphertext(ciphertext)
  );

  // Clock generation
  initial begin
    enable = 0;
    #5 enable = 0;
    #5 enable = 1;
    #5 enable = 0;
  end

  initial begin
    $dumpfile("dump.vcd");
    $dumpvars;
  end

  // Test vectors for ciphertext and key
  initial begin
    
    ciphertext = 128'hf3eed1bdb5d2a03c064b5a7e3db181f8;  
    key = 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4;  

    // Apply reset
    reset = 1;
    #5 reset = 0;

    // Wait for some time to see the result
    #1000000;

    // End simulation
    $stop;
  end

  // Monitor the results
  initial begin
    $display("At time %0t, plaintext = %h", $time, ciphertext);
    $display("At time %0t, key = %h", $time, key);
    $monitor("At time %0t, Plaintext = %h", $time, plaintext);

  end

endmodule
