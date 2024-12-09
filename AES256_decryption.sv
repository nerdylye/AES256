// Code your design here
// Code your design here

//`include "sbox.sv"

module aes_256(
  input logic enable,
  input logic reset,
  input  [127:0] ciphertext,
  input logic [255:0] key,
  output logic [127:0] plaintext);

  logic [7:0] state [3:0][3:0];
  logic [31:0] roundkeys [0:59];
  logic [7:0] sbox_data_in, sbox_data_out;

  // declare round constant for AES-256
  // odd round constants has value, even round constants are 0
  logic [31:0] RC [1:15] = {
    32'h01000000,
    32'h00000000,
    32'h02000000,
    32'h00000000,
    32'h04000000,
    32'h00000000,
    32'h08000000,
    32'h00000000,
    32'h10000000,
    32'h00000000,
    32'h20000000,
    32'h00000000,
    32'h40000000,
    32'h00000000,
    32'h80000000};


  always_ff @(posedge enable) begin
    if (reset) begin
      plaintext <= 128'h0;
    end

    else begin  
      for(int round = 14; round >= 0; round--) begin
        if (round == 14) begin
          array_16(ciphertext); // converts plaintext into 4x4 array of 8-bit each element
          keyexpand(key); // run key expansion algorithm
          $display("roundkeys");
          $display(roundkeys);
          $display("\nBefore round %d", round);
          display_state();

          // round 14 only consists of addroundkeys
          $display("roundkeys[%d] = %h",round*4, roundkeys[(round*4)]);
          $display("roundkeys[%d] = %h",round*4+1, roundkeys[(round*4+1)]);
          $display("roundkeys[%d] = %h",round*4+2, roundkeys[(round*4+2)]);
          $display("roundkeys[%d] = %h",round*4+3, roundkeys[(round*4+3)]);
          addroundkey(state, {roundkeys[round*4], roundkeys[round*4+1], roundkeys[round*4+2], roundkeys[round*4+3]}); 
          $display("After round %d", round);
          display_state();
        end
        else if (round == 0) begin
          // last round consists of inv_shiftrows, inv_subbytes and addroundkeys
          inv_shiftrows(state);
          inv_subbytes();
          addroundkey(state, {roundkeys[round*4], roundkeys[round*4+1], roundkeys[round*4+2], roundkeys[round*4+3]});
          $display("\nAfter last round");
          display_state();
          flatten_array(); // convert the 4x4 array back to a string of plaintext
        end
        else begin
          // inv_shiftrows
          $display("\nAt round%d :", round);
          inv_shiftrows(state);
          $display("\nAfter inv_shiftrows");
          display_state();

          // inv_subbytes
          inv_subbytes();
          $display("\nAfter shiftrows");
          display_state();

          // addroundkeys
          $display("roundkeys[%d] = %h",round*4, roundkeys[(round*4)]);
          $display("roundkeys[%d] = %h",round*4+1, roundkeys[(round*4+1)]);
          $display("roundkeys[%d] = %h",round*4+2, roundkeys[(round*4+2)]);
          $display("roundkeys[%d] = %h",round*4+3, roundkeys[(round*4+3)]);
          addroundkey(state, {roundkeys[(round*4)], roundkeys[(round*4+1)], roundkeys[(round*4+2)], roundkeys[(round*4+3)]});
          $display("\nAfter addroundkey%d", round);
          display_state();
          
          // inv_mixcolumns
          inv_mixcolumns(state);
          $display("\nAfter inv_mixcolumns");
          display_state();
        end
      end
    end
  end


  function void display_state();
    for (int i = 0; i < 4; i++) begin
      $display("%h %h %h %h", state[i][0], state[i][1], state[i][2], state[i][3]);
    end
  endfunction


  function void flatten_array ();
    // convert 4x4 array to text
    begin
      plaintext[127:120] = state[0][0]; // First byte
      plaintext[119:112] = state[0][1];
      plaintext[111:104] = state[0][2];
      plaintext[103:96] = state[0][3];

      plaintext[95:88] = state[1][0];
      plaintext[87:80] = state[1][1];
      plaintext[79:72] = state[1][2];
      plaintext[71:64] = state[1][3];

      plaintext[63:56] = state[2][0];
      plaintext[55:48] = state[2][1];
      plaintext[47:40] = state[2][2];
      plaintext[39:32] = state[2][3];

      plaintext[31:24] = state[3][0];
      plaintext[23:16] = state[3][1];
      plaintext[15:8] = state[3][2];
      plaintext[7:0] = state[3][3];     // Last byte
    end 
  endfunction


  function void array_16 (input logic [127:0] plaintext);
    // convert text to 4x4 array, each element consists of a byte(8-bits) 
    begin
      state[0][0] = ciphertext[127:120]; // First byte
      state[0][1] = ciphertext[119:112];
      state[0][2] = ciphertext[111:104];
      state[0][3] = ciphertext[103:96];

      state[1][0] = ciphertext[95:88];
      state[1][1] = ciphertext[87:80];
      state[1][2] = ciphertext[79:72];
      state[1][3] = ciphertext[71:64];

      state[2][0] = ciphertext[63:56];
      state[2][1] = ciphertext[55:48];
      state[2][2] = ciphertext[47:40];
      state[2][3] = ciphertext[39:32];

      state[3][0] = ciphertext[31:24];
      state[3][1] = ciphertext[23:16];
      state[3][2] = ciphertext[15:8];
      state[3][3] = ciphertext[7:0];     // Last byte
    end 
  endfunction


  function void keyexpand (input logic [255:0] key);
    begin
      logic [31:0] gword;

      // Copy the original key to the first eight round keys
      roundkeys[0] = key[255:224];
      roundkeys[1] = key[223:192];
      roundkeys[2] = key[191:160];
      roundkeys[3] = key[159:128];
      roundkeys[4] = key[127:96];
      roundkeys[5] = key[95:64];
      roundkeys[6] = key[63:32];
      roundkeys[7] = key[31:0];

      // Display initial round keys
      for (int i = 0; i < 8; i++) begin
        $display("roundkeys[%0d] = %h", i, roundkeys[i]);
      end

      // Key expansion algorithm
      for (int i = 8; i < 60; i++) begin
        if (i % 4 == 0) begin
          gword = G(roundkeys[i-1], i/4 - 1); // Run the G function 
          roundkeys[i] = roundkeys[i-8] ^ gword; // previous 8th roundkeys XOR gword
          $display("roundkeys[%d] ^ G(%d) : %h ^ %h", i-8, i-1, roundkeys[i-8], gword);
        end 
        else begin
          roundkeys[i] = roundkeys[i-1] ^ roundkeys[i-8]; // previous 8th roundkeys XOR previous 1 roundkey
          $display("roundkeys[%d] ^ roundkeys[%d] : %h ^ %h", i-1, i-8, roundkeys[i-1], roundkeys[i-8]);
        end
        $display("roundkeys[%d] = %h", i, roundkeys[i]);
      end

      for (int a = 0; a < 60; a++) begin
        $display("roundkey[%d] = %h", a, roundkeys[a]);
      end

    end
  endfunction


  // G Function
  function logic [31:0] G (input logic [31:0] word, input int round);
    logic [7:0] B [0:3];
    begin
      // Even rounds does not require rotate word
      if (round % 2 == 0) begin
        B[0] = word[31:24];
        B[1] = word[23:16];
        B[2] = word[15:8];
        B[3] = word[7:0];
      end

      else begin
        // word rotation for odd rounds
        B[3] = word[31:24];
        B[0] = word[23:16];
        B[1] = word[15:8];
        B[2] = word[7:0];
      end

      $display("begin G function of round = %d", round);
      $display("word_in = %h", word);      
      $display("B = %h", {B[0],B[1],B[2],B[3]});

      // Substitute bytes using the S-box
      for (int i = 0; i < 4; i++) begin
        sbox_data_in = B[i];
        sbox(sbox_data_in, sbox_data_out);
        $display("sbox_data_in = %h", sbox_data_in);
        $display("sbox_data_out = %h", sbox_data_out);
        B[i] = sbox_data_out;  
      end

      word[31:24] = B[0];
      word[23:16] = B[1];
      word[15:8] = B[2];
      word[7:0] = B[3];

      //XOR with round constant
      $display("word ^ RC[%d] : %h ^ %h", round, word, RC[round]);
      word = word ^ RC[round];
      $display("word_out = %h", word);
    end
    return word;
  endfunction


  // SubBytes function: Apply S-box substitution to the state
  function void inv_subbytes();
    // Loop through each byte in the state
    for (int i = 0; i < 4; i++) begin
      for (int j = 0; j < 4; j++) begin
        // Send the current state byte to the S-box
        sbox_data_in = state[i][j];
        inv_sbox(sbox_data_in, sbox_data_out);
        //  $display("sbox_data_in = %h", sbox_data_in);
        //  $display("sbox_data_out = %h", sbox_data_out);
        state[i][j] = sbox_data_out;
      end
    end
  endfunction


  function void inv_shiftrows (input logic [7:0] array [3:0][3:0]);
    // shift rows according to fixed pattern

    // first row remains
    state[0][0] = array[0][0];
    state[1][0] = array[1][0];
    state[2][0] = array[2][0];
    state[3][0] = array[3][0];

    // second row shift left by 1
    state[0][1] = array[3][1];
    state[1][1] = array[0][1];
    state[2][1] = array[1][1];
    state[3][1] = array[2][1];

    // third row shift left by 2
    state[0][2] = array[2][2];
    state[1][2] = array[3][2];
    state[2][2] = array[0][2];
    state[3][2] = array[1][2];

    // fourth row shift left by 3
    state[0][3] = array[1][3];
    state[1][3] = array[2][3];
    state[2][3] = array[3][3];
    state[3][3] = array[0][3];
  endfunction


  function void inv_mixcolumns(input logic [7:0] array[3:0][3:0]);
    logic [7:0] a0, a1, a2, a3;
    //    $display("Input State:");
    //    for (int i = 0; i < 4; i++) begin
    //      $display("%h %h %h %h", array[i][0], array[i][1], array[i][2], array[i][3]);
    //    end

    for (int j = 0; j < 4; j++) begin
      a0 = array[j][0];
      a1 = array[j][1];
      a2 = array[j][2];
      a3 = array[j][3];

      // Calculate using Galois Field multiplication
      state[j][0] = mb0e(a0) ^ mb0b(a1) ^ mb0d(a2) ^ mb09(a3);
      state[j][1] = mb09(a0) ^ mb0e(a1) ^ mb0b(a2) ^ mb0d(a3);
      state[j][2] = mb0d(a0) ^ mb09(a1) ^ mb0e(a2) ^ mb0b(a3);
      state[j][3] = mb0b(a0) ^ mb0d(a1) ^ mb09(a2) ^ mb0e(a3);
    end 

    //    $display("State After MixColumns:");
    //    for (int i = 0; i < 4; i++) begin
    //      $display("%h %h %h %h", state[i][0], state[i][1], state[i][2], state[i][3]);
    //    end
  endfunction

  // ------------------------------------------------------------------------------------------//
  //This function multiply by {02} n-times
  function[7:0] multiply(input [7:0]x,input integer n);
    integer i;
    begin
      for(i=0;i<n;i=i+1)begin
        if(x[7] == 1) x = ((x << 1) ^ 8'h1b);
        else x = x << 1; 
      end
      multiply=x;
    end

  endfunction


  /* 
      Multiply by {0e} is done by :
      (multiplying by {02} 3 times which is equivalent to multiplication by {08}) xor
      (multiplying by {02} 2 times which is equivalent to multiplication by {04}) xor
      (multiplying by {02})
      so that 8+4+2= e. where xor is the addition of elements in finite fields
  */
  function [7:0] mb0e; //multiply by {0e}
    input [7:0] x;
    begin
      mb0e=multiply(x,3) ^ multiply(x,2)^ multiply(x,1);
    end
  endfunction

  /* 
      Multiply by {0d} is done by :
      (multiplying by {02} 3 times which is equivalent to multiplication by {08}) xor
      (multiplying by {02} 2 times which is equivalent to multiplication by {04}) xor
      (the original x)
      so that 8+4+1= d. where xor is the addition of elements in finite fields
  */
  function [7:0] mb0d; //multiply by {0d}
    input [7:0] x;
    begin
      mb0d=multiply(x,3) ^ multiply(x,2)^ x;
    end
  endfunction


  /* 
      Multiply by {0b} is done by :
      (multiplying by {02} 3 times which is equivalent to multiplication by {08}) xor
      (multiplying by {02}) xor (the original x)
      so that 8+2+1= b. where xor is the addition of elements in finite fields
  */

  function [7:0] mb0b;  //multiply by {0b}
    input [7:0] x;
    begin
      mb0b=multiply(x,3) ^ multiply(x,1)^ x;
    end
  endfunction
  /* 
      Multiply by {09} is done by :
      (multiplying by {02} 3 times which is equivalent to multiplication by {08}) xor (the original x)
      so that 8+1= 9. where xor is the addition of elements in finite fields
  */

  function [7:0] mb09; //multiply by {09}
    input [7:0] x;
    begin
      mb09=multiply(x,3) ^  x;
    end
  endfunction

  // ------------------------------------------------------------------------------------------//


  function void addroundkey (input logic [7:0] array [3:0][3:0], input logic [31:0] roundkeys [0:3]);
    logic [7:0] matrix [3:0][3:0];
    begin
      matrix[0][0] = roundkeys[0][31:24];
      matrix[0][1] = roundkeys[0][23:16];
      matrix[0][2] = roundkeys[0][15:8];
      matrix[0][3] = roundkeys[0][7:0];

      matrix[1][0] = roundkeys[1][31:24];
      matrix[1][1] = roundkeys[1][23:16];
      matrix[1][2] = roundkeys[1][15:8];
      matrix[1][3] = roundkeys[1][7:0];

      matrix[2][0] = roundkeys[2][31:24];
      matrix[2][1] = roundkeys[2][23:16];
      matrix[2][2] = roundkeys[2][15:8];
      matrix[2][3] = roundkeys[2][7:0];

      matrix[3][0] = roundkeys[3][31:24];
      matrix[3][1] = roundkeys[3][23:16];
      matrix[3][2] = roundkeys[3][15:8];
      matrix[3][3] = roundkeys[3][7:0];
      
      $display("Original State:");
      for (int i = 0; i < 4; i++) begin
        $display("%h %h %h %h", array[i][0], array[i][1], array[i][2], array[i][3]);
      end
      
      $display("Matrix:");
      for (int i = 0; i < 4; i++) begin
        $display("%h %h %h %h", matrix[i][0], matrix[i][1], matrix[i][2], matrix[i][3]);
      end

      // XOR function of roundkeys and state array
      for (int i = 0; i < 4; i++) begin
        for (int j = 0; j < 4; j++) begin
          state[i][j] = array[i][j] ^ matrix[i][j];
        end
      end
    end
  endfunction

  

  // inv_sbox task for inverse substitute bytes
  task inv_sbox(input logic [7:0] data,
                output logic [7:0] dout);
    begin
      // $display("data_in = %h", data);

      case (data)          //substitution table
        8'h00			:	dout =8'h52;
        8'h01			:	dout =8'h09;
        8'h02			:	dout =8'h6a;
        8'h03			:	dout =8'hd5;
        8'h04			:	dout =8'h30;
        8'h05			:	dout =8'h36;
        8'h06			:	dout =8'ha5;
        8'h07			:	dout =8'h38;
        8'h08			:	dout =8'hbf;
        8'h09			:	dout =8'h40;
        8'h0a			:	dout =8'ha3;
        8'h0b			:	dout =8'h9e;
        8'h0c			:	dout =8'h81;
        8'h0d			:	dout =8'hf3;
        8'h0e			:	dout =8'hd7;
        8'h0f			:	dout =8'hfb;
        /***************************************/
        8'h10			:	dout =8'h7c;
        8'h11			:	dout =8'he3;
        8'h12			:	dout =8'h39;
        8'h13			:	dout =8'h82;
        8'h14			:	dout =8'h9b;
        8'h15			:	dout =8'h2f;
        8'h16			:	dout =8'hff;
        8'h17			:	dout =8'h87;
        8'h18			:	dout =8'h34;
        8'h19			:	dout =8'h8e;
        8'h1a			:	dout =8'h43;
        8'h1b			:	dout =8'h44;
        8'h1c			:	dout =8'hc4;
        8'h1d			:	dout =8'hde;
        8'h1e			:	dout =8'he9;
        8'h1f			:	dout =8'hcb;
        /*********************************************/
        8'h20			:	dout =8'h54;
        8'h21			:	dout =8'h7b;
        8'h22			:	dout =8'h94;
        8'h23			:	dout =8'h32;
        8'h24			:	dout =8'ha6;
        8'h25			:	dout =8'hc2;
        8'h26			:	dout =8'h23;
        8'h27			:	dout =8'h3d;
        8'h28			:	dout =8'hee;
        8'h29			:	dout =8'h4c;
        8'h2a			:	dout =8'h95;
        8'h2b			:	dout =8'h0b;
        8'h2c			:	dout =8'h42;
        8'h2d			:	dout =8'hfa;
        8'h2e			:	dout =8'hc3;
        8'h2f			:	dout =8'h4e;
        /****************************************/
        8'h30			:	dout =8'h08;
        8'h31			:	dout =8'h2e;
        8'h32			:	dout =8'ha1;
        8'h33			:	dout =8'h66;
        8'h34			:	dout =8'h28;
        8'h35			:	dout =8'hd9;
        8'h36			:	dout =8'h24;
        8'h37			:	dout =8'hb2;
        8'h38			:	dout =8'h76;
        8'h39			:	dout =8'h5b;
        8'h3a			:	dout =8'ha2;
        8'h3b			:	dout =8'h49;
        8'h3c			:	dout =8'h6d;
        8'h3d			:	dout =8'h8b;
        8'h3e			:	dout =8'hd1;
        8'h3f			:	dout =8'h25;
        /******************************************/
        8'h40			:	dout =8'h72;
        8'h41			:	dout =8'hf8;
        8'h42			:	dout =8'hf6;
        8'h43			:	dout =8'h64;
        8'h44			:	dout =8'h86;
        8'h45			:	dout =8'h68;
        8'h46			:	dout =8'h98;
        8'h47			:	dout =8'h16;
        8'h48			:	dout =8'hd4;
        8'h49			:	dout =8'ha4;
        8'h4a			:	dout =8'h5c;
        8'h4b			:	dout =8'hcc;
        8'h4c			:	dout =8'h5d;
        8'h4d			:	dout =8'h65;
        8'h4e			:	dout =8'hb6;
        8'h4f			:	dout =8'h92;
        /*********************************************/
        8'h50			:	dout =8'h6c;
        8'h51			:	dout =8'h70;
        8'h52			:	dout =8'h48;
        8'h53			:	dout =8'h50;
        8'h54			:	dout =8'hfd;
        8'h55			:	dout =8'hed;
        8'h56			:	dout =8'hb9;
        8'h57			:	dout =8'hda;
        8'h58			:	dout =8'h5e;
        8'h59			:	dout =8'h15;
        8'h5a			:	dout =8'h46;
        8'h5b			:	dout =8'h57;
        8'h5c			:	dout =8'ha7;
        8'h5d			:	dout =8'h8d;
        8'h5e			:	dout =8'h9d;
        8'h5f			:	dout =8'h84;
        /***************************************/
        8'h60			:	dout =8'h90;
        8'h61			:	dout =8'hd8;
        8'h62			:	dout =8'hab;
        8'h63			:	dout =8'h00;
        8'h64			:	dout =8'h8c;
        8'h65			:	dout =8'hbc;
        8'h66			:	dout =8'hd3;
        8'h67			:	dout =8'h0a;
        8'h68			:	dout =8'hf7;
        8'h69			:	dout =8'he4;
        8'h6a			:	dout =8'h58;
        8'h6b			:	dout =8'h05;
        8'h6c			:	dout =8'hb8;
        8'h6d			:	dout =8'hb3;
        8'h6e			:	dout =8'h45;
        8'h6f			:	dout =8'h06;
        /********************************************/
        8'h70			:	dout =8'hd0;
        8'h71			:	dout =8'h2c;
        8'h72			:	dout =8'h1e;
        8'h73			:	dout =8'h8f;
        8'h74			:	dout =8'hca;
        8'h75			:	dout =8'h3f;
        8'h76			:	dout =8'h0f;
        8'h77			:	dout =8'h02;
        8'h78			:	dout =8'hc1;
        8'h79			:	dout =8'haf;
        8'h7a			:	dout =8'hbd;
        8'h7b			:	dout =8'h03;
        8'h7c			:	dout =8'h01;
        8'h7d			:	dout =8'h13;
        8'h7e			:	dout =8'h8a;
        8'h7f			:	dout =8'h6b;
        /*******************************************/
        8'h80			:	dout =8'h3a;
        8'h81			:	dout =8'h91;
        8'h82			:	dout =8'h11;
        8'h83			:	dout =8'h41;
        8'h84			:	dout =8'h4f;
        8'h85			:	dout =8'h67;
        8'h86			:	dout =8'hdc;
        8'h87			:	dout =8'hea;
        8'h88			:	dout =8'h97;
        8'h89			:	dout =8'hf2;
        8'h8a			:	dout =8'hcf;
        8'h8b			:	dout =8'hce;
        8'h8c			:	dout =8'hf0;
        8'h8d			:	dout =8'hb4;
        8'h8e			:	dout =8'he6;
        8'h8f			:	dout =8'h73;
        /**********************************************/
        8'h90			:	dout =8'h96;
        8'h91			:	dout =8'hac;
        8'h92			:	dout =8'h74;
        8'h93			:	dout =8'h22;
        8'h94			:	dout =8'he7;
        8'h95			:	dout =8'had;
        8'h96			:	dout =8'h35;
        8'h97			:	dout =8'h85;
        8'h98			:	dout =8'he2;
        8'h99			:	dout =8'hf9;
        8'h9a			:	dout =8'h37;
        8'h9b			:	dout =8'he8;
        8'h9c			:	dout =8'h1c;
        8'h9d			:	dout =8'h75;
        8'h9e			:	dout =8'hdf;
        8'h9f			:	dout =8'h6e;
        /*****************************************/
        8'ha0			:	dout =8'h47;
        8'ha1			:	dout =8'hf1;
        8'ha2			:	dout =8'h1a;
        8'ha3			:	dout =8'h71;
        8'ha4			:	dout =8'h1d;
        8'ha5			:	dout =8'h29;
        8'ha6			:	dout =8'hc5;
        8'ha7			:	dout =8'h89;
        8'ha8			:	dout =8'h6f;
        8'ha9			:	dout =8'hb7;
        8'haa			:	dout =8'h62;
        8'hab			:	dout =8'h0e;
        8'hac			:	dout =8'haa;
        8'had			:	dout =8'h18;
        8'hae			:	dout =8'hbe;
        8'haf			:	dout =8'h1b;
        /*****************************************/
        8'hb0			:	dout =8'hfc;
        8'hb1			:	dout =8'h56;
        8'hb2			:	dout =8'h3e;
        8'hb3			:	dout =8'h4b;
        8'hb4			:	dout =8'hc6;
        8'hb5			:	dout =8'hd2;
        8'hb6			:	dout =8'h79;
        8'hb7			:	dout =8'h20;
        8'hb8			:	dout =8'h9a;
        8'hb9			:	dout =8'hdb;
        8'hba			:	dout =8'hc0;
        8'hbb			:	dout =8'hfe;
        8'hbc			:	dout =8'h78;
        8'hbd			:	dout =8'hcd;
        8'hbe			:	dout =8'h5a;
        8'hbf			:	dout =8'hf4;
        /***************************************/
        8'hc0			:	dout =8'h1f;
        8'hc1			:	dout =8'hdd;
        8'hc2			:	dout =8'ha8;
        8'hc3			:	dout =8'h33;
        8'hc4			:	dout =8'h88;
        8'hc5			:	dout =8'h07;
        8'hc6			:	dout =8'hc7;
        8'hc7			:	dout =8'h31;
        8'hc8			:	dout =8'hb1;
        8'hc9			:	dout =8'h12;
        8'hca			:	dout =8'h10;
        8'hcb			:	dout =8'h59;
        8'hcc			:	dout =8'h27;
        8'hcd			:	dout =8'h80;
        8'hce			:	dout =8'hec;
        8'hcf			:	dout =8'h5f;
        /***************************************/
        8'hd0			:	dout =8'h60;
        8'hd1			:	dout =8'h51;
        8'hd2			:	dout =8'h7f;
        8'hd3			:	dout =8'ha9;
        8'hd4			:	dout =8'h19;
        8'hd5			:	dout =8'hb5;
        8'hd6			:	dout =8'h4a;
        8'hd7			:	dout =8'h0d;
        8'hd8			:	dout =8'h2d;
        8'hd9			:	dout =8'he5;
        8'hda			:	dout =8'h7a;
        8'hdb			:	dout =8'h9f;
        8'hdc			:	dout =8'h93;
        8'hdd			:	dout =8'hc9;
        8'hde			:	dout =8'h9c;
        8'hdf			:	dout =8'hef;
        /******************************************/
        8'he0			:	dout =8'ha0;
        8'he1			:	dout =8'he0;
        8'he2			:	dout =8'h3b;
        8'he3			:	dout =8'h4d;
        8'he4			:	dout =8'hae;
        8'he5			:	dout =8'h2a;
        8'he6			:	dout =8'hf5;
        8'he7			:	dout =8'hb0;
        8'he8			:	dout =8'hc8;
        8'he9			:	dout =8'heb;
        8'hea			:	dout =8'hbb;
        8'heb			:	dout =8'h3c;
        8'hec			:	dout =8'h83;
        8'hed			:	dout =8'h53;
        8'hee			:	dout =8'h99;
        8'hef			:	dout =8'h61;
        /****************************************/
        8'hf0			:	dout =8'h17;
        8'hf1			:	dout =8'h2b;
        8'hf2			:	dout =8'h04;
        8'hf3			:	dout =8'h7e;
        8'hf4			:	dout =8'hba;
        8'hf5			:	dout =8'h77;
        8'hf6			:	dout =8'hd6;
        8'hf7			:	dout =8'h26;
        8'hf8			:	dout =8'he1;
        8'hf9			:	dout =8'h69;
        8'hfa			:	dout =8'h14;
        8'hfb			:	dout =8'h63;
        8'hfc			:	dout =8'h55;
        8'hfd			:	dout =8'h21;
        8'hfe			:	dout =8'h0c;
        8'hff			:	dout =8'h7d;
      endcase
    end
  endtask
  
  // sbox task for g function 
  task sbox(input logic [7:0] data,
            output logic [7:0] dout);
    begin
      // $display("data_in = %h", data);

      case (data)          //substitution table
        8'h00              : dout = 8'h63;
        8'h01              : dout = 8'h7c;
        8'h02              : dout = 8'h77;
        8'h03              : dout = 8'h7b;
        8'h04              : dout = 8'hf2;
        8'h05              : dout = 8'h6b;
        8'h06              : dout = 8'h6f;
        8'h07              : dout = 8'hc5;
        8'h08              : dout = 8'h30;
        8'h09              : dout = 8'h01;
        8'h0a              : dout = 8'h67;
        8'h0b              : dout = 8'h2b;
        8'h0c              : dout = 8'hfe;
        8'h0d              : dout = 8'hd7;
        8'h0e              : dout = 8'hab;
        8'h0f              : dout = 8'h76;
        /***************************************/
        8'h10              : dout = 8'hca;
        8'h11              : dout = 8'h82;
        8'h12              : dout = 8'hc9;
        8'h13              : dout = 8'h7d;
        8'h14              : dout = 8'hfa;
        8'h15              : dout = 8'h59;
        8'h16              : dout = 8'h47;
        8'h17              : dout = 8'hf0;
        8'h18              : dout = 8'had;
        8'h19              : dout = 8'hd4;
        8'h1a              : dout = 8'ha2;
        8'h1b              : dout = 8'haf;
        8'h1c              : dout = 8'h9c;
        8'h1d              : dout = 8'ha4;
        8'h1e              : dout = 8'h72;
        8'h1f              : dout = 8'hc0;
        /*********************************************/
        8'h20              : dout = 8'hb7;
        8'h21              : dout = 8'hfd;
        8'h22              : dout = 8'h93;
        8'h23              : dout = 8'h26;
        8'h24              : dout = 8'h36;
        8'h25              : dout = 8'h3f;
        8'h26              : dout = 8'hf7;
        8'h27              : dout = 8'hcc;
        8'h28              : dout = 8'h34;
        8'h29              : dout = 8'ha5;
        8'h2a              : dout = 8'he5;
        8'h2b              : dout = 8'hf1;
        8'h2c              : dout = 8'h71;
        8'h2d              : dout = 8'hd8;
        8'h2e              : dout = 8'h31;
        8'h2f              : dout = 8'h15;
        /***************************************/
        8'h30              : dout = 8'h04;
        8'h31              : dout = 8'hc7;
        8'h32              : dout = 8'h23;
        8'h33              : dout = 8'hc3;
        8'h34              : dout = 8'h18;
        8'h35              : dout = 8'h96;
        8'h36              : dout = 8'h05;
        8'h37              : dout = 8'h9a;
        8'h38              : dout = 8'h07;
        8'h39              : dout = 8'h12;
        8'h3a              : dout = 8'h80;
        8'h3b              : dout = 8'he2;
        8'h3c              : dout = 8'heb;
        8'h3d              : dout = 8'h27;
        8'h3e              : dout = 8'hb2;
        8'h3f              : dout = 8'h75;
        /******************************************/
        8'h40              : dout = 8'h09;
        8'h41              : dout = 8'h83;
        8'h42              : dout = 8'h2c;
        8'h43              : dout = 8'h1a;
        8'h44              : dout = 8'h1b;
        8'h45              : dout = 8'h6e;
        8'h46              : dout = 8'h5a;
        8'h47              : dout = 8'ha0;
        8'h48              : dout = 8'h52;
        8'h49              : dout = 8'h3b;
        8'h4a              : dout = 8'hd6;
        8'h4b              : dout = 8'hb3;
        8'h4c              : dout = 8'h29;
        8'h4d              : dout = 8'he3;
        8'h4e              : dout = 8'h2f;
        8'h4f              : dout = 8'h84;
        /*********************************************/
        8'h50              : dout = 8'h53;
        8'h51              : dout = 8'hd1;
        8'h52              : dout = 8'h00;
        8'h53              : dout = 8'hed;
        8'h54              : dout = 8'h20;
        8'h55              : dout = 8'hfc;
        8'h56              : dout = 8'hb1;
        8'h57              : dout = 8'h5b;
        8'h58              : dout = 8'h6a;
        8'h59              : dout = 8'hcb;
        8'h5a              : dout = 8'hbe;
        8'h5b              : dout = 8'h39;
        8'h5c              : dout = 8'h4a;
        8'h5d              : dout = 8'h4c;
        8'h5e              : dout = 8'h58;
        8'h5f              : dout = 8'hcf;
        /***************************************/
        8'h60              : dout = 8'hd0;
        8'h61              : dout = 8'hef;
        8'h62              : dout = 8'haa;
        8'h63              : dout = 8'hfb;
        8'h64              : dout = 8'h43;
        8'h65              : dout = 8'h4d;
        8'h66              : dout = 8'h33;
        8'h67              : dout = 8'h85;
        8'h68              : dout = 8'h45;
        8'h69              : dout = 8'hf9;
        8'h6a              : dout = 8'h02;
        8'h6b              : dout = 8'h7f;
        8'h6c              : dout = 8'h50;
        8'h6d              : dout = 8'h3c;
        8'h6e              : dout = 8'h9f;
        8'h6f              : dout = 8'ha8;
        /********************************************/
        8'h70              : dout = 8'h51;
        8'h71              : dout = 8'ha3;
        8'h72              : dout = 8'h40;
        8'h73              : dout = 8'h8f;
        8'h74              : dout = 8'h92;
        8'h75              : dout = 8'h9d;
        8'h76              : dout = 8'h38;
        8'h77              : dout = 8'hf5;
        8'h78              : dout = 8'hbc;
        8'h79              : dout = 8'hb6;
        8'h7a              : dout = 8'hda;
        8'h7b              : dout = 8'h21;
        8'h7c              : dout = 8'h10;
        8'h7d              : dout = 8'hff;
        8'h7e              : dout = 8'hf3;
        8'h7f              : dout = 8'hd2;
        /*******************************************/
        8'h80              : dout = 8'hcd;
        8'h81              : dout = 8'h0c;
        8'h82              : dout = 8'h13;
        8'h83              : dout = 8'hec;
        8'h84              : dout = 8'h5f;
        8'h85              : dout = 8'h97;
        8'h86              : dout = 8'h44;
        8'h87              : dout = 8'h17;
        8'h88              : dout = 8'hc4;
        8'h89              : dout = 8'ha7;
        8'h8a              : dout = 8'h7e;
        8'h8b              : dout = 8'h3d;
        8'h8c              : dout = 8'h64;
        8'h8d              : dout = 8'h5d;
        8'h8e              : dout = 8'h19;
        8'h8f              : dout = 8'h73;
        /**********************************************/
        8'h90              : dout = 8'h60;
        8'h91              : dout = 8'h81;
        8'h92              : dout = 8'h4f;
        8'h93              : dout = 8'hdc;
        8'h94              : dout = 8'h22;
        8'h95              : dout = 8'h2a;
        8'h96              : dout = 8'h90;
        8'h97              : dout = 8'h88;
        8'h98              : dout = 8'h46;
        8'h99              : dout = 8'hee;
        8'h9a              : dout = 8'hb8;
        8'h9b              : dout = 8'h14;
        8'h9c              : dout = 8'hde;
        8'h9d              : dout = 8'h5e;
        8'h9e              : dout = 8'h0b;
        8'h9f              : dout = 8'hdb;
        /*****************************************/
        8'ha0              : dout = 8'he0;
        8'ha1              : dout = 8'h32;
        8'ha2              : dout = 8'h3a;
        8'ha3              : dout = 8'h0a;
        8'ha4              : dout = 8'h49;
        8'ha5              : dout = 8'h06;
        8'ha6              : dout = 8'h24;
        8'ha7              : dout = 8'h5c;
        8'ha8              : dout = 8'hc2;
        8'ha9              : dout = 8'hd3;
        8'haa              : dout = 8'hac;
        8'hab              : dout = 8'h62;
        8'hac              : dout = 8'h91;
        8'had              : dout = 8'h95;
        8'hae              : dout = 8'he4;
        8'haf              : dout = 8'h79;
        /*****************************************/
        8'hb0              : dout = 8'he7;
        8'hb1              : dout = 8'hc8;
        8'hb2              : dout = 8'h37;
        8'hb3              : dout = 8'h6d;
        8'hb4              : dout = 8'h8d;
        8'hb5              : dout = 8'hd5;
        8'hb6              : dout = 8'h4e;
        8'hb7              : dout = 8'ha9;
        8'hb8              : dout = 8'h6c;
        8'hb9              : dout = 8'h56;
        8'hba              : dout = 8'hf4;
        8'hbb              : dout = 8'hea;
        8'hbc              : dout = 8'h65;
        8'hbd              : dout = 8'h7a;
        8'hbe              : dout = 8'hae;
        8'hbf              : dout = 8'h08;
        /***************************************/
        8'hc0              : dout = 8'hba;
        8'hc1              : dout = 8'h78;
        8'hc2              : dout = 8'h25;
        8'hc3              : dout = 8'h2e;
        8'hc4              : dout = 8'h1c;
        8'hc5              : dout = 8'ha6;
        8'hc6              : dout = 8'hb4;
        8'hc7              : dout = 8'hc6;
        8'hc8              : dout = 8'he8;
        8'hc9              : dout = 8'hdd;
        8'hca              : dout = 8'h74;
        8'hcb              : dout = 8'h1f;
        8'hcc              : dout = 8'h4b;
        8'hcd              : dout = 8'hbd;
        8'hce              : dout = 8'h8b;
        8'hcf              : dout = 8'h8a;
        /***************************************/
        8'hd0              : dout = 8'h70;
        8'hd1              : dout = 8'h3e;
        8'hd2              : dout = 8'hb5;
        8'hd3              : dout = 8'h66;
        8'hd4              : dout = 8'h48;
        8'hd5              : dout = 8'h03;
        8'hd6              : dout = 8'hf6;
        8'hd7              : dout = 8'h0e;
        8'hd8              : dout = 8'h61;
        8'hd9              : dout = 8'h35;
        8'hda              : dout = 8'h57;
        8'hdb              : dout = 8'hb9;
        8'hdc              : dout = 8'h86;
        8'hdd              : dout = 8'hc1;
        8'hde              : dout = 8'h1d;
        8'hdf              : dout = 8'h9e;
        /******************************************/
        8'he0              : dout = 8'he1;
        8'he1              : dout = 8'hf8;
        8'he2              : dout = 8'h98;
        8'he3              : dout = 8'h11;
        8'he4              : dout = 8'h69;
        8'he5              : dout = 8'hd9;
        8'he6              : dout = 8'h8e;
        8'he7              : dout = 8'h94;
        8'he8              : dout = 8'h9b;
        8'he9              : dout = 8'h1e;
        8'hea              : dout = 8'h87;
        8'heb              : dout = 8'he9;
        8'hec              : dout = 8'hce;
        8'hed              : dout = 8'h55;
        8'hee              : dout = 8'h28;
        8'hef              : dout = 8'hdf;
        /****************************************/
        8'hf0              : dout = 8'h8c;
        8'hf1              : dout = 8'ha1;
        8'hf2              : dout = 8'h89;
        8'hf3              : dout = 8'h0d;
        8'hf4              : dout = 8'hbf;
        8'hf5              : dout = 8'he6;
        8'hf6              : dout = 8'h42;
        8'hf7              : dout = 8'h68;
        8'hf8              : dout = 8'h41;
        8'hf9              : dout = 8'h99;
        8'hfa              : dout = 8'h2d;
        8'hfb              : dout = 8'h0f;
        8'hfc              : dout = 8'hb0;
        8'hfd              : dout = 8'h54;
        8'hfe              : dout = 8'hbb;
        8'hff              : dout = 8'h16;
        default            : dout = 8'h00;
      endcase
    end
  endtask


endmodule
