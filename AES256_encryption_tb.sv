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

  // Test vectors for plaintext and key
  initial begin
    // Convert "helloworld" to hexadecimal (ASCII values):
    // 'h' = 68, 'e' = 65, 'l' = 6C, 'o' = 6F, 'w' = 77, 'r' = 72, 'd' = 64
    plaintext = 128'h6bc1bee22e409f96e93d7e117393172a;  // "helloworld" padded to 16 bytes

    // Convert "abcdefghijklmnopqrstuvwxyz123456" to hexadecimal
    key = 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4;  // "abcdefghijklmnopqrstuvwxyz123456"

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
    $display("At time %0t, plaintext = %h", $time, plaintext);
    $display("At time %0t, key = %h", $time, key);
    $monitor("At time %0t, Ciphertext = %h", $time, ciphertext);

  end

endmodule
