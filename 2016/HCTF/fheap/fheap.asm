
./fheap:     file format elf64-x86-64


Disassembly of section .init:

0000000000000930 <.init>:
 930:	48 83 ec 08          	sub    $0x8,%rsp
 934:	48 8b 05 9d 16 20 00 	mov    0x20169d(%rip),%rax        # 201fd8 <__cxa_finalize@plt+0x201598>
 93b:	48 85 c0             	test   %rax,%rax
 93e:	74 05                	je     945 <free@plt-0x1b>
 940:	e8 bb 00 00 00       	callq  a00 <__gmon_start__@plt>
 945:	48 83 c4 08          	add    $0x8,%rsp
 949:	c3                   	retq   

Disassembly of section .plt:

0000000000000950 <free@plt-0x10>:
 950:	ff 35 b2 16 20 00    	pushq  0x2016b2(%rip)        # 202008 <__cxa_finalize@plt+0x2015c8>
 956:	ff 25 b4 16 20 00    	jmpq   *0x2016b4(%rip)        # 202010 <__cxa_finalize@plt+0x2015d0>
 95c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000000960 <free@plt>:
 960:	ff 25 b2 16 20 00    	jmpq   *0x2016b2(%rip)        # 202018 <__cxa_finalize@plt+0x2015d8>
 966:	68 00 00 00 00       	pushq  $0x0
 96b:	e9 e0 ff ff ff       	jmpq   950 <free@plt-0x10>

0000000000000970 <strncpy@plt>:
 970:	ff 25 aa 16 20 00    	jmpq   *0x2016aa(%rip)        # 202020 <__cxa_finalize@plt+0x2015e0>
 976:	68 01 00 00 00       	pushq  $0x1
 97b:	e9 d0 ff ff ff       	jmpq   950 <free@plt-0x10>

0000000000000980 <strncmp@plt>:
 980:	ff 25 a2 16 20 00    	jmpq   *0x2016a2(%rip)        # 202028 <__cxa_finalize@plt+0x2015e8>
 986:	68 02 00 00 00       	pushq  $0x2
 98b:	e9 c0 ff ff ff       	jmpq   950 <free@plt-0x10>

0000000000000990 <puts@plt>:
 990:	ff 25 9a 16 20 00    	jmpq   *0x20169a(%rip)        # 202030 <__cxa_finalize@plt+0x2015f0>
 996:	68 03 00 00 00       	pushq  $0x3
 99b:	e9 b0 ff ff ff       	jmpq   950 <free@plt-0x10>

00000000000009a0 <strlen@plt>:
 9a0:	ff 25 92 16 20 00    	jmpq   *0x201692(%rip)        # 202038 <__cxa_finalize@plt+0x2015f8>
 9a6:	68 04 00 00 00       	pushq  $0x4
 9ab:	e9 a0 ff ff ff       	jmpq   950 <free@plt-0x10>

00000000000009b0 <__stack_chk_fail@plt>:
 9b0:	ff 25 8a 16 20 00    	jmpq   *0x20168a(%rip)        # 202040 <__cxa_finalize@plt+0x201600>
 9b6:	68 05 00 00 00       	pushq  $0x5
 9bb:	e9 90 ff ff ff       	jmpq   950 <free@plt-0x10>

00000000000009c0 <setbuf@plt>:
 9c0:	ff 25 82 16 20 00    	jmpq   *0x201682(%rip)        # 202048 <__cxa_finalize@plt+0x201608>
 9c6:	68 06 00 00 00       	pushq  $0x6
 9cb:	e9 80 ff ff ff       	jmpq   950 <free@plt-0x10>

00000000000009d0 <printf@plt>:
 9d0:	ff 25 7a 16 20 00    	jmpq   *0x20167a(%rip)        # 202050 <__cxa_finalize@plt+0x201610>
 9d6:	68 07 00 00 00       	pushq  $0x7
 9db:	e9 70 ff ff ff       	jmpq   950 <free@plt-0x10>

00000000000009e0 <read@plt>:
 9e0:	ff 25 72 16 20 00    	jmpq   *0x201672(%rip)        # 202058 <__cxa_finalize@plt+0x201618>
 9e6:	68 08 00 00 00       	pushq  $0x8
 9eb:	e9 60 ff ff ff       	jmpq   950 <free@plt-0x10>

00000000000009f0 <__libc_start_main@plt>:
 9f0:	ff 25 6a 16 20 00    	jmpq   *0x20166a(%rip)        # 202060 <__cxa_finalize@plt+0x201620>
 9f6:	68 09 00 00 00       	pushq  $0x9
 9fb:	e9 50 ff ff ff       	jmpq   950 <free@plt-0x10>

0000000000000a00 <__gmon_start__@plt>:
 a00:	ff 25 62 16 20 00    	jmpq   *0x201662(%rip)        # 202068 <__cxa_finalize@plt+0x201628>
 a06:	68 0a 00 00 00       	pushq  $0xa
 a0b:	e9 40 ff ff ff       	jmpq   950 <free@plt-0x10>

0000000000000a10 <malloc@plt>:
 a10:	ff 25 5a 16 20 00    	jmpq   *0x20165a(%rip)        # 202070 <__cxa_finalize@plt+0x201630>
 a16:	68 0b 00 00 00       	pushq  $0xb
 a1b:	e9 30 ff ff ff       	jmpq   950 <free@plt-0x10>

0000000000000a20 <atoi@plt>:
 a20:	ff 25 52 16 20 00    	jmpq   *0x201652(%rip)        # 202078 <__cxa_finalize@plt+0x201638>
 a26:	68 0c 00 00 00       	pushq  $0xc
 a2b:	e9 20 ff ff ff       	jmpq   950 <free@plt-0x10>

0000000000000a30 <exit@plt>:
 a30:	ff 25 4a 16 20 00    	jmpq   *0x20164a(%rip)        # 202080 <__cxa_finalize@plt+0x201640>
 a36:	68 0d 00 00 00       	pushq  $0xd
 a3b:	e9 10 ff ff ff       	jmpq   950 <free@plt-0x10>

0000000000000a40 <__cxa_finalize@plt>:
 a40:	ff 25 42 16 20 00    	jmpq   *0x201642(%rip)        # 202088 <__cxa_finalize@plt+0x201648>
 a46:	68 0e 00 00 00       	pushq  $0xe
 a4b:	e9 00 ff ff ff       	jmpq   950 <free@plt-0x10>

Disassembly of section .text:

0000000000000a50 <.text>:
     a50:	31 ed                	xor    %ebp,%ebp
     a52:	49 89 d1             	mov    %rdx,%r9
     a55:	5e                   	pop    %rsi
     a56:	48 89 e2             	mov    %rsp,%rdx
     a59:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
     a5d:	50                   	push   %rax
     a5e:	54                   	push   %rsp
     a5f:	4c 8d 05 8a 07 00 00 	lea    0x78a(%rip),%r8        # 11f0 <__cxa_finalize@plt+0x7b0>
     a66:	48 8d 0d 13 07 00 00 	lea    0x713(%rip),%rcx        # 1180 <__cxa_finalize@plt+0x740>
     a6d:	48 8d 3d 7a 01 00 00 	lea    0x17a(%rip),%rdi        # bee <__cxa_finalize@plt+0x1ae>
     a74:	e8 77 ff ff ff       	callq  9f0 <__libc_start_main@plt>
     a79:	f4                   	hlt    
     a7a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
     a80:	48 8d 05 20 16 20 00 	lea    0x201620(%rip),%rax        # 2020a7 <_edata@@Base+0x7>
     a87:	48 8d 3d 12 16 20 00 	lea    0x201612(%rip),%rdi        # 2020a0 <_edata@@Base>
     a8e:	55                   	push   %rbp
     a8f:	48 29 f8             	sub    %rdi,%rax
     a92:	48 89 e5             	mov    %rsp,%rbp
     a95:	48 83 f8 0e          	cmp    $0xe,%rax
     a99:	77 02                	ja     a9d <__cxa_finalize@plt+0x5d>
     a9b:	5d                   	pop    %rbp
     a9c:	c3                   	retq   
     a9d:	48 8b 05 1c 15 20 00 	mov    0x20151c(%rip),%rax        # 201fc0 <__cxa_finalize@plt+0x201580>
     aa4:	48 85 c0             	test   %rax,%rax
     aa7:	74 f2                	je     a9b <__cxa_finalize@plt+0x5b>
     aa9:	5d                   	pop    %rbp
     aaa:	ff e0                	jmpq   *%rax
     aac:	0f 1f 40 00          	nopl   0x0(%rax)
     ab0:	48 8d 05 e9 15 20 00 	lea    0x2015e9(%rip),%rax        # 2020a0 <_edata@@Base>
     ab7:	48 8d 3d e2 15 20 00 	lea    0x2015e2(%rip),%rdi        # 2020a0 <_edata@@Base>
     abe:	55                   	push   %rbp
     abf:	48 29 f8             	sub    %rdi,%rax
     ac2:	48 89 e5             	mov    %rsp,%rbp
     ac5:	48 c1 f8 03          	sar    $0x3,%rax
     ac9:	48 89 c2             	mov    %rax,%rdx
     acc:	48 c1 ea 3f          	shr    $0x3f,%rdx
     ad0:	48 01 d0             	add    %rdx,%rax
     ad3:	48 d1 f8             	sar    %rax
     ad6:	75 02                	jne    ada <__cxa_finalize@plt+0x9a>
     ad8:	5d                   	pop    %rbp
     ad9:	c3                   	retq   
     ada:	48 8b 15 07 15 20 00 	mov    0x201507(%rip),%rdx        # 201fe8 <__cxa_finalize@plt+0x2015a8>
     ae1:	48 85 d2             	test   %rdx,%rdx
     ae4:	74 f2                	je     ad8 <__cxa_finalize@plt+0x98>
     ae6:	5d                   	pop    %rbp
     ae7:	48 89 c6             	mov    %rax,%rsi
     aea:	ff e2                	jmpq   *%rdx
     aec:	0f 1f 40 00          	nopl   0x0(%rax)
     af0:	80 3d a9 15 20 00 00 	cmpb   $0x0,0x2015a9(%rip)        # 2020a0 <_edata@@Base>
     af7:	75 27                	jne    b20 <__cxa_finalize@plt+0xe0>
     af9:	48 83 3d ef 14 20 00 	cmpq   $0x0,0x2014ef(%rip)        # 201ff0 <__cxa_finalize@plt+0x2015b0>
     b00:	00 
     b01:	55                   	push   %rbp
     b02:	48 89 e5             	mov    %rsp,%rbp
     b05:	74 0c                	je     b13 <__cxa_finalize@plt+0xd3>
     b07:	48 8b 3d 8a 15 20 00 	mov    0x20158a(%rip),%rdi        # 202098 <__cxa_finalize@plt+0x201658>
     b0e:	e8 2d ff ff ff       	callq  a40 <__cxa_finalize@plt>
     b13:	e8 68 ff ff ff       	callq  a80 <__cxa_finalize@plt+0x40>
     b18:	5d                   	pop    %rbp
     b19:	c6 05 80 15 20 00 01 	movb   $0x1,0x201580(%rip)        # 2020a0 <_edata@@Base>
     b20:	f3 c3                	repz retq 
     b22:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 nopw %cs:0x0(%rax,%rax,1)
     b29:	1f 84 00 00 00 00 00 
     b30:	48 83 3d b0 12 20 00 	cmpq   $0x0,0x2012b0(%rip)        # 201de8 <__cxa_finalize@plt+0x2013a8>
     b37:	00 
     b38:	74 26                	je     b60 <__cxa_finalize@plt+0x120>
     b3a:	48 8b 05 9f 14 20 00 	mov    0x20149f(%rip),%rax        # 201fe0 <__cxa_finalize@plt+0x2015a0>
     b41:	48 85 c0             	test   %rax,%rax
     b44:	74 1a                	je     b60 <__cxa_finalize@plt+0x120>
     b46:	55                   	push   %rbp
     b47:	48 8d 3d 9a 12 20 00 	lea    0x20129a(%rip),%rdi        # 201de8 <__cxa_finalize@plt+0x2013a8>
     b4e:	48 89 e5             	mov    %rsp,%rbp
     b51:	ff d0                	callq  *%rax
     b53:	5d                   	pop    %rbp
     b54:	e9 57 ff ff ff       	jmpq   ab0 <__cxa_finalize@plt+0x70>
     b59:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
     b60:	e9 4b ff ff ff       	jmpq   ab0 <__cxa_finalize@plt+0x70>
     b65:	55                   	push   %rbp
     b66:	48 89 e5             	mov    %rsp,%rbp
     b69:	48 83 ec 30          	sub    $0x30,%rsp
     b6d:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
     b74:	00 00 
     b76:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
     b7a:	31 c0                	xor    %eax,%eax
     b7c:	c7 45 dc 00 00 00 00 	movl   $0x0,-0x24(%rbp)
     b83:	eb 11                	jmp    b96 <__cxa_finalize@plt+0x156>
     b85:	0f b6 55 db          	movzbl -0x25(%rbp),%edx
     b89:	8b 45 dc             	mov    -0x24(%rbp),%eax
     b8c:	48 98                	cltq   
     b8e:	88 54 05 e0          	mov    %dl,-0x20(%rbp,%rax,1)
     b92:	83 45 dc 01          	addl   $0x1,-0x24(%rbp)
     b96:	48 8d 45 db          	lea    -0x25(%rbp),%rax
     b9a:	ba 01 00 00 00       	mov    $0x1,%edx
     b9f:	48 89 c6             	mov    %rax,%rsi
     ba2:	bf 00 00 00 00       	mov    $0x0,%edi
     ba7:	e8 34 fe ff ff       	callq  9e0 <read@plt>
     bac:	0f b6 45 db          	movzbl -0x25(%rbp),%eax
     bb0:	3c 0a                	cmp    $0xa,%al
     bb2:	74 0e                	je     bc2 <__cxa_finalize@plt+0x182>
     bb4:	83 7d dc 09          	cmpl   $0x9,-0x24(%rbp)
     bb8:	7f 08                	jg     bc2 <__cxa_finalize@plt+0x182>
     bba:	0f b6 45 db          	movzbl -0x25(%rbp),%eax
     bbe:	3c ff                	cmp    $0xff,%al
     bc0:	75 c3                	jne    b85 <__cxa_finalize@plt+0x145>
     bc2:	8b 45 dc             	mov    -0x24(%rbp),%eax
     bc5:	48 98                	cltq   
     bc7:	c6 44 05 e0 00       	movb   $0x0,-0x20(%rbp,%rax,1)
     bcc:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
     bd0:	48 89 c7             	mov    %rax,%rdi
     bd3:	e8 48 fe ff ff       	callq  a20 <atoi@plt>
     bd8:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
     bdc:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
     be3:	00 00 
     be5:	74 05                	je     bec <__cxa_finalize@plt+0x1ac>
     be7:	e8 c4 fd ff ff       	callq  9b0 <__stack_chk_fail@plt>
     bec:	c9                   	leaveq 
     bed:	c3                   	retq   
     bee:	55                   	push   %rbp
     bef:	48 89 e5             	mov    %rsp,%rbp
     bf2:	48 81 ec 10 04 00 00 	sub    $0x410,%rsp
     bf9:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
     c00:	00 00 
     c02:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
     c06:	31 c0                	xor    %eax,%eax
     c08:	48 8b 05 b9 13 20 00 	mov    0x2013b9(%rip),%rax        # 201fc8 <__cxa_finalize@plt+0x201588>
     c0f:	48 8b 00             	mov    (%rax),%rax
     c12:	be 00 00 00 00       	mov    $0x0,%esi
     c17:	48 89 c7             	mov    %rax,%rdi
     c1a:	e8 a1 fd ff ff       	callq  9c0 <setbuf@plt>
     c1f:	48 8b 05 aa 13 20 00 	mov    0x2013aa(%rip),%rax        # 201fd0 <__cxa_finalize@plt+0x201590>
     c26:	48 8b 00             	mov    (%rax),%rax
     c29:	be 00 00 00 00       	mov    $0x0,%esi
     c2e:	48 89 c7             	mov    %rax,%rdi
     c31:	e8 8a fd ff ff       	callq  9c0 <setbuf@plt>
     c36:	48 8b 05 bb 13 20 00 	mov    0x2013bb(%rip),%rax        # 201ff8 <__cxa_finalize@plt+0x2015b8>
     c3d:	48 8b 00             	mov    (%rax),%rax
     c40:	be 00 00 00 00       	mov    $0x0,%esi
     c45:	48 89 c7             	mov    %rax,%rdi
     c48:	e8 73 fd ff ff       	callq  9c0 <setbuf@plt>
     c4d:	48 8d 3d b4 05 00 00 	lea    0x5b4(%rip),%rdi        # 1208 <__cxa_finalize@plt+0x7c8>
     c54:	e8 37 fd ff ff       	callq  990 <puts@plt>
     c59:	48 8d 3d c4 05 00 00 	lea    0x5c4(%rip),%rdi        # 1224 <__cxa_finalize@plt+0x7e4>
     c60:	e8 2b fd ff ff       	callq  990 <puts@plt>
     c65:	48 8d 3d 9c 05 00 00 	lea    0x59c(%rip),%rdi        # 1208 <__cxa_finalize@plt+0x7c8>
     c6c:	e8 1f fd ff ff       	callq  990 <puts@plt>
     c71:	e8 d5 04 00 00       	callq  114b <__cxa_finalize@plt+0x70b>
     c76:	48 8d 85 f0 fb ff ff 	lea    -0x410(%rbp),%rax
     c7d:	ba 00 04 00 00       	mov    $0x400,%edx
     c82:	48 89 c6             	mov    %rax,%rsi
     c85:	bf 00 00 00 00       	mov    $0x0,%edi
     c8a:	e8 51 fd ff ff       	callq  9e0 <read@plt>
     c8f:	48 85 c0             	test   %rax,%rax
     c92:	75 0a                	jne    c9e <__cxa_finalize@plt+0x25e>
     c94:	b8 01 00 00 00       	mov    $0x1,%eax
     c99:	e9 9e 00 00 00       	jmpq   d3c <__cxa_finalize@plt+0x2fc>
     c9e:	48 8d 85 f0 fb ff ff 	lea    -0x410(%rbp),%rax
     ca5:	ba 07 00 00 00       	mov    $0x7,%edx
     caa:	48 8d 35 8d 05 00 00 	lea    0x58d(%rip),%rsi        # 123e <__cxa_finalize@plt+0x7fe>
     cb1:	48 89 c7             	mov    %rax,%rdi
     cb4:	e8 c7 fc ff ff       	callq  980 <strncmp@plt>
     cb9:	85 c0                	test   %eax,%eax
     cbb:	75 0c                	jne    cc9 <__cxa_finalize@plt+0x289>
     cbd:	b8 00 00 00 00       	mov    $0x0,%eax
     cc2:	e8 01 02 00 00       	callq  ec8 <__cxa_finalize@plt+0x488>
     cc7:	eb 6e                	jmp    d37 <__cxa_finalize@plt+0x2f7>
     cc9:	48 8d 85 f0 fb ff ff 	lea    -0x410(%rbp),%rax
     cd0:	ba 07 00 00 00       	mov    $0x7,%edx
     cd5:	48 8d 35 6a 05 00 00 	lea    0x56a(%rip),%rsi        # 1246 <__cxa_finalize@plt+0x806>
     cdc:	48 89 c7             	mov    %rax,%rdi
     cdf:	e8 9c fc ff ff       	callq  980 <strncmp@plt>
     ce4:	85 c0                	test   %eax,%eax
     ce6:	75 0c                	jne    cf4 <__cxa_finalize@plt+0x2b4>
     ce8:	b8 00 00 00 00       	mov    $0x0,%eax
     ced:	e8 a3 00 00 00       	callq  d95 <__cxa_finalize@plt+0x355>
     cf2:	eb 43                	jmp    d37 <__cxa_finalize@plt+0x2f7>
     cf4:	48 8d 85 f0 fb ff ff 	lea    -0x410(%rbp),%rax
     cfb:	ba 05 00 00 00       	mov    $0x5,%edx
     d00:	48 8d 35 47 05 00 00 	lea    0x547(%rip),%rsi        # 124e <__cxa_finalize@plt+0x80e>
     d07:	48 89 c7             	mov    %rax,%rdi
     d0a:	e8 71 fc ff ff       	callq  980 <strncmp@plt>
     d0f:	85 c0                	test   %eax,%eax
     d11:	75 13                	jne    d26 <__cxa_finalize@plt+0x2e6>
     d13:	48 8d 3d 3a 05 00 00 	lea    0x53a(%rip),%rdi        # 1254 <__cxa_finalize@plt+0x814>
     d1a:	e8 71 fc ff ff       	callq  990 <puts@plt>
     d1f:	b8 00 00 00 00       	mov    $0x0,%eax
     d24:	eb 16                	jmp    d3c <__cxa_finalize@plt+0x2fc>
     d26:	48 8d 3d 2c 05 00 00 	lea    0x52c(%rip),%rdi        # 1259 <__cxa_finalize@plt+0x819>
     d2d:	e8 5e fc ff ff       	callq  990 <puts@plt>
     d32:	e9 3a ff ff ff       	jmpq   c71 <__cxa_finalize@plt+0x231>
     d37:	e9 35 ff ff ff       	jmpq   c71 <__cxa_finalize@plt+0x231>
     d3c:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
     d40:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
     d47:	00 00 
     d49:	74 05                	je     d50 <__cxa_finalize@plt+0x310>
     d4b:	e8 60 fc ff ff       	callq  9b0 <__stack_chk_fail@plt>
     d50:	c9                   	leaveq 
     d51:	c3                   	retq   
     d52:	55                   	push   %rbp
     d53:	48 89 e5             	mov    %rsp,%rbp
     d56:	48 83 ec 10          	sub    $0x10,%rsp
     d5a:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
     d5e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
     d62:	48 89 c7             	mov    %rax,%rdi
     d65:	e8 f6 fb ff ff       	callq  960 <free@plt>
     d6a:	c9                   	leaveq 
     d6b:	c3                   	retq   
     d6c:	55                   	push   %rbp
     d6d:	48 89 e5             	mov    %rsp,%rbp
     d70:	48 83 ec 10          	sub    $0x10,%rsp
     d74:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
     d78:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
     d7c:	48 8b 00             	mov    (%rax),%rax
     d7f:	48 89 c7             	mov    %rax,%rdi
     d82:	e8 d9 fb ff ff       	callq  960 <free@plt>
     d87:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
     d8b:	48 89 c7             	mov    %rax,%rdi
     d8e:	e8 cd fb ff ff       	callq  960 <free@plt>
     d93:	c9                   	leaveq 
     d94:	c3                   	retq   
     d95:	55                   	push   %rbp
     d96:	48 89 e5             	mov    %rsp,%rbp
     d99:	48 81 ec 20 01 00 00 	sub    $0x120,%rsp
     da0:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
     da7:	00 00 
     da9:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
     dad:	31 c0                	xor    %eax,%eax
     daf:	48 8d 3d b2 04 00 00 	lea    0x4b2(%rip),%rdi        # 1268 <__cxa_finalize@plt+0x828>
     db6:	b8 00 00 00 00       	mov    $0x0,%eax
     dbb:	e8 10 fc ff ff       	callq  9d0 <printf@plt>
     dc0:	e8 a0 fd ff ff       	callq  b65 <__cxa_finalize@plt+0x125>
     dc5:	89 85 ec fe ff ff    	mov    %eax,-0x114(%rbp)
     dcb:	83 bd ec fe ff ff 00 	cmpl   $0x0,-0x114(%rbp)
     dd2:	78 09                	js     ddd <__cxa_finalize@plt+0x39d>
     dd4:	83 bd ec fe ff ff 10 	cmpl   $0x10,-0x114(%rbp)
     ddb:	7e 0c                	jle    de9 <__cxa_finalize@plt+0x3a9>
     ddd:	48 8d 3d b5 04 00 00 	lea    0x4b5(%rip),%rdi        # 1299 <__cxa_finalize@plt+0x859>
     de4:	e8 a7 fb ff ff       	callq  990 <puts@plt>
     de9:	48 8d 05 d0 12 20 00 	lea    0x2012d0(%rip),%rax        # 2020c0 <_edata@@Base+0x20>
     df0:	8b 95 ec fe ff ff    	mov    -0x114(%rbp),%edx
     df6:	48 63 d2             	movslq %edx,%rdx
     df9:	48 c1 e2 04          	shl    $0x4,%rdx
     dfd:	48 01 d0             	add    %rdx,%rax
     e00:	48 8b 40 08          	mov    0x8(%rax),%rax
     e04:	48 85 c0             	test   %rax,%rax
     e07:	0f 84 a5 00 00 00    	je     eb2 <__cxa_finalize@plt+0x472>
     e0d:	48 8d 3d 90 04 00 00 	lea    0x490(%rip),%rdi        # 12a4 <__cxa_finalize@plt+0x864>
     e14:	b8 00 00 00 00       	mov    $0x0,%eax
     e19:	e8 b2 fb ff ff       	callq  9d0 <printf@plt>
     e1e:	48 8d 85 f0 fe ff ff 	lea    -0x110(%rbp),%rax
     e25:	ba 00 01 00 00       	mov    $0x100,%edx
     e2a:	48 89 c6             	mov    %rax,%rsi
     e2d:	bf 00 00 00 00       	mov    $0x0,%edi
     e32:	e8 a9 fb ff ff       	callq  9e0 <read@plt>
     e37:	48 8d 85 f0 fe ff ff 	lea    -0x110(%rbp),%rax
     e3e:	ba 03 00 00 00       	mov    $0x3,%edx
     e43:	48 8d 35 69 04 00 00 	lea    0x469(%rip),%rsi        # 12b3 <__cxa_finalize@plt+0x873>
     e4a:	48 89 c7             	mov    %rax,%rdi
     e4d:	e8 2e fb ff ff       	callq  980 <strncmp@plt>
     e52:	85 c0                	test   %eax,%eax
     e54:	75 5c                	jne    eb2 <__cxa_finalize@plt+0x472>
     e56:	48 8d 05 63 12 20 00 	lea    0x201263(%rip),%rax        # 2020c0 <_edata@@Base+0x20>
     e5d:	8b 95 ec fe ff ff    	mov    -0x114(%rbp),%edx
     e63:	48 63 d2             	movslq %edx,%rdx
     e66:	48 c1 e2 04          	shl    $0x4,%rdx
     e6a:	48 01 d0             	add    %rdx,%rax
     e6d:	48 8b 40 08          	mov    0x8(%rax),%rax
     e71:	48 8b 40 18          	mov    0x18(%rax),%rax
     e75:	48 8d 15 44 12 20 00 	lea    0x201244(%rip),%rdx        # 2020c0 <_edata@@Base+0x20>
     e7c:	8b 8d ec fe ff ff    	mov    -0x114(%rbp),%ecx
     e82:	48 63 c9             	movslq %ecx,%rcx
     e85:	48 c1 e1 04          	shl    $0x4,%rcx
     e89:	48 01 ca             	add    %rcx,%rdx
     e8c:	48 8b 52 08          	mov    0x8(%rdx),%rdx
     e90:	48 89 d7             	mov    %rdx,%rdi
     e93:	ff d0                	callq  *%rax
     e95:	48 8d 05 24 12 20 00 	lea    0x201224(%rip),%rax        # 2020c0 <_edata@@Base+0x20>
     e9c:	8b 95 ec fe ff ff    	mov    -0x114(%rbp),%edx
     ea2:	48 63 d2             	movslq %edx,%rdx
     ea5:	48 c1 e2 04          	shl    $0x4,%rdx
     ea9:	48 01 d0             	add    %rdx,%rax
     eac:	c7 00 00 00 00 00    	movl   $0x0,(%rax)
     eb2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
     eb6:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
     ebd:	00 00 
     ebf:	74 05                	je     ec6 <__cxa_finalize@plt+0x486>
     ec1:	e8 ea fa ff ff       	callq  9b0 <__stack_chk_fail@plt>
     ec6:	c9                   	leaveq 
     ec7:	c3                   	retq   
     ec8:	55                   	push   %rbp
     ec9:	48 89 e5             	mov    %rsp,%rbp
     ecc:	48 81 ec 30 10 00 00 	sub    $0x1030,%rsp
     ed3:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
     eda:	00 00 
     edc:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
     ee0:	31 c0                	xor    %eax,%eax
     ee2:	bf 20 00 00 00       	mov    $0x20,%edi
     ee7:	e8 24 fb ff ff       	callq  a10 <malloc@plt>
     eec:	48 89 85 d8 ef ff ff 	mov    %rax,-0x1028(%rbp)
     ef3:	48 c7 85 e0 ef ff ff 	movq   $0x0,-0x1020(%rbp)
     efa:	00 00 00 00 
     efe:	48 8d 3d b2 03 00 00 	lea    0x3b2(%rip),%rdi        # 12b7 <__cxa_finalize@plt+0x877>
     f05:	b8 00 00 00 00       	mov    $0x0,%eax
     f0a:	e8 c1 fa ff ff       	callq  9d0 <printf@plt>
     f0f:	e8 51 fc ff ff       	callq  b65 <__cxa_finalize@plt+0x125>
     f14:	48 98                	cltq   
     f16:	48 89 85 e8 ef ff ff 	mov    %rax,-0x1018(%rbp)
     f1d:	48 81 bd e8 ef ff ff 	cmpq   $0x1000,-0x1018(%rbp)
     f24:	00 10 00 00 
     f28:	76 20                	jbe    f4a <__cxa_finalize@plt+0x50a>
     f2a:	48 8d 3d 9c 03 00 00 	lea    0x39c(%rip),%rdi        # 12cd <__cxa_finalize@plt+0x88d>
     f31:	e8 5a fa ff ff       	callq  990 <puts@plt>
     f36:	48 8b 85 d8 ef ff ff 	mov    -0x1028(%rbp),%rax
     f3d:	48 89 c7             	mov    %rax,%rdi
     f40:	e8 1b fa ff ff       	callq  960 <free@plt>
     f45:	e9 eb 01 00 00       	jmpq   1135 <__cxa_finalize@plt+0x6f5>
     f4a:	48 8d 3d 89 03 00 00 	lea    0x389(%rip),%rdi        # 12da <__cxa_finalize@plt+0x89a>
     f51:	b8 00 00 00 00       	mov    $0x0,%eax
     f56:	e8 75 fa ff ff       	callq  9d0 <printf@plt>
     f5b:	48 8b 95 e8 ef ff ff 	mov    -0x1018(%rbp),%rdx
     f62:	48 8d 85 f0 ef ff ff 	lea    -0x1010(%rbp),%rax
     f69:	48 89 c6             	mov    %rax,%rsi
     f6c:	bf 00 00 00 00       	mov    $0x0,%edi
     f71:	e8 6a fa ff ff       	callq  9e0 <read@plt>
     f76:	48 83 f8 ff          	cmp    $0xffffffffffffffff,%rax
     f7a:	75 16                	jne    f92 <__cxa_finalize@plt+0x552>
     f7c:	48 8d 3d 5c 03 00 00 	lea    0x35c(%rip),%rdi        # 12df <__cxa_finalize@plt+0x89f>
     f83:	e8 08 fa ff ff       	callq  990 <puts@plt>
     f88:	bf 01 00 00 00       	mov    $0x1,%edi
     f8d:	e8 9e fa ff ff       	callq  a30 <exit@plt>
     f92:	48 8d 85 f0 ef ff ff 	lea    -0x1010(%rbp),%rax
     f99:	48 89 c7             	mov    %rax,%rdi
     f9c:	e8 ff f9 ff ff       	callq  9a0 <strlen@plt>
     fa1:	48 89 85 e8 ef ff ff 	mov    %rax,-0x1018(%rbp)
     fa8:	48 83 bd e8 ef ff ff 	cmpq   $0xf,-0x1018(%rbp)
     faf:	0f 
     fb0:	77 34                	ja     fe6 <__cxa_finalize@plt+0x5a6>
     fb2:	48 8b 85 d8 ef ff ff 	mov    -0x1028(%rbp),%rax
     fb9:	48 8b 95 e8 ef ff ff 	mov    -0x1018(%rbp),%rdx
     fc0:	48 8d 8d f0 ef ff ff 	lea    -0x1010(%rbp),%rcx
     fc7:	48 89 ce             	mov    %rcx,%rsi
     fca:	48 89 c7             	mov    %rax,%rdi
     fcd:	e8 9e f9 ff ff       	callq  970 <strncpy@plt>
     fd2:	48 8b 85 d8 ef ff ff 	mov    -0x1028(%rbp),%rax
     fd9:	48 8d 15 72 fd ff ff 	lea    -0x28e(%rip),%rdx        # d52 <__cxa_finalize@plt+0x312>
     fe0:	48 89 50 18          	mov    %rdx,0x18(%rax)
     fe4:	eb 79                	jmp    105f <__cxa_finalize@plt+0x61f>
     fe6:	48 8b 85 e8 ef ff ff 	mov    -0x1018(%rbp),%rax
     fed:	48 89 c7             	mov    %rax,%rdi
     ff0:	e8 1b fa ff ff       	callq  a10 <malloc@plt>
     ff5:	48 89 85 e0 ef ff ff 	mov    %rax,-0x1020(%rbp)
     ffc:	48 83 bd e0 ef ff ff 	cmpq   $0x0,-0x1020(%rbp)
    1003:	00 
    1004:	75 16                	jne    101c <__cxa_finalize@plt+0x5dc>
    1006:	48 8d 3d dc 02 00 00 	lea    0x2dc(%rip),%rdi        # 12e9 <__cxa_finalize@plt+0x8a9>
    100d:	e8 7e f9 ff ff       	callq  990 <puts@plt>
    1012:	bf 01 00 00 00       	mov    $0x1,%edi
    1017:	e8 14 fa ff ff       	callq  a30 <exit@plt>
    101c:	48 8b 95 e8 ef ff ff 	mov    -0x1018(%rbp),%rdx
    1023:	48 8d 8d f0 ef ff ff 	lea    -0x1010(%rbp),%rcx
    102a:	48 8b 85 e0 ef ff ff 	mov    -0x1020(%rbp),%rax
    1031:	48 89 ce             	mov    %rcx,%rsi
    1034:	48 89 c7             	mov    %rax,%rdi
    1037:	e8 34 f9 ff ff       	callq  970 <strncpy@plt>
    103c:	48 8b 85 d8 ef ff ff 	mov    -0x1028(%rbp),%rax
    1043:	48 8b 95 e0 ef ff ff 	mov    -0x1020(%rbp),%rdx
    104a:	48 89 10             	mov    %rdx,(%rax)
    104d:	48 8b 85 d8 ef ff ff 	mov    -0x1028(%rbp),%rax
    1054:	48 8d 15 11 fd ff ff 	lea    -0x2ef(%rip),%rdx        # d6c <__cxa_finalize@plt+0x32c>
    105b:	48 89 50 18          	mov    %rdx,0x18(%rax)
    105f:	48 8b 85 e8 ef ff ff 	mov    -0x1018(%rbp),%rax
    1066:	89 c2                	mov    %eax,%edx
    1068:	48 8b 85 d8 ef ff ff 	mov    -0x1028(%rbp),%rax
    106f:	89 50 10             	mov    %edx,0x10(%rax)
    1072:	c7 85 d4 ef ff ff 00 	movl   $0x0,-0x102c(%rbp)
    1079:	00 00 00 
    107c:	eb 7e                	jmp    10fc <__cxa_finalize@plt+0x6bc>
    107e:	48 8d 05 3b 10 20 00 	lea    0x20103b(%rip),%rax        # 2020c0 <_edata@@Base+0x20>
    1085:	8b 95 d4 ef ff ff    	mov    -0x102c(%rbp),%edx
    108b:	48 63 d2             	movslq %edx,%rdx
    108e:	48 c1 e2 04          	shl    $0x4,%rdx
    1092:	48 01 d0             	add    %rdx,%rax
    1095:	8b 00                	mov    (%rax),%eax
    1097:	85 c0                	test   %eax,%eax
    1099:	75 5a                	jne    10f5 <__cxa_finalize@plt+0x6b5>
    109b:	48 8d 05 1e 10 20 00 	lea    0x20101e(%rip),%rax        # 2020c0 <_edata@@Base+0x20>
    10a2:	8b 95 d4 ef ff ff    	mov    -0x102c(%rbp),%edx
    10a8:	48 63 d2             	movslq %edx,%rdx
    10ab:	48 c1 e2 04          	shl    $0x4,%rdx
    10af:	48 01 d0             	add    %rdx,%rax
    10b2:	c7 00 01 00 00 00    	movl   $0x1,(%rax)
    10b8:	48 8d 05 01 10 20 00 	lea    0x201001(%rip),%rax        # 2020c0 <_edata@@Base+0x20>
    10bf:	8b 95 d4 ef ff ff    	mov    -0x102c(%rbp),%edx
    10c5:	48 63 d2             	movslq %edx,%rdx
    10c8:	48 c1 e2 04          	shl    $0x4,%rdx
    10cc:	48 01 c2             	add    %rax,%rdx
    10cf:	48 8b 85 d8 ef ff ff 	mov    -0x1028(%rbp),%rax
    10d6:	48 89 42 08          	mov    %rax,0x8(%rdx)
    10da:	8b 85 d4 ef ff ff    	mov    -0x102c(%rbp),%eax
    10e0:	89 c6                	mov    %eax,%esi
    10e2:	48 8d 3d 0e 02 00 00 	lea    0x20e(%rip),%rdi        # 12f7 <__cxa_finalize@plt+0x8b7>
    10e9:	b8 00 00 00 00       	mov    $0x0,%eax
    10ee:	e8 dd f8 ff ff       	callq  9d0 <printf@plt>
    10f3:	eb 14                	jmp    1109 <__cxa_finalize@plt+0x6c9>
    10f5:	83 85 d4 ef ff ff 01 	addl   $0x1,-0x102c(%rbp)
    10fc:	83 bd d4 ef ff ff 0f 	cmpl   $0xf,-0x102c(%rbp)
    1103:	0f 8e 75 ff ff ff    	jle    107e <__cxa_finalize@plt+0x63e>
    1109:	83 bd d4 ef ff ff 10 	cmpl   $0x10,-0x102c(%rbp)
    1110:	75 23                	jne    1135 <__cxa_finalize@plt+0x6f5>
    1112:	48 8d 3d f3 01 00 00 	lea    0x1f3(%rip),%rdi        # 130c <__cxa_finalize@plt+0x8cc>
    1119:	e8 72 f8 ff ff       	callq  990 <puts@plt>
    111e:	48 8b 85 d8 ef ff ff 	mov    -0x1028(%rbp),%rax
    1125:	48 8b 40 18          	mov    0x18(%rax),%rax
    1129:	48 8b 95 d8 ef ff ff 	mov    -0x1028(%rbp),%rdx
    1130:	48 89 d7             	mov    %rdx,%rdi
    1133:	ff d0                	callq  *%rax
    1135:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1139:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
    1140:	00 00 
    1142:	74 05                	je     1149 <__cxa_finalize@plt+0x709>
    1144:	e8 67 f8 ff ff       	callq  9b0 <__stack_chk_fail@plt>
    1149:	c9                   	leaveq 
    114a:	c3                   	retq   
    114b:	55                   	push   %rbp
    114c:	48 89 e5             	mov    %rsp,%rbp
    114f:	48 8d 3d ce 01 00 00 	lea    0x1ce(%rip),%rdi        # 1324 <__cxa_finalize@plt+0x8e4>
    1156:	e8 35 f8 ff ff       	callq  990 <puts@plt>
    115b:	48 8d 3d d2 01 00 00 	lea    0x1d2(%rip),%rdi        # 1334 <__cxa_finalize@plt+0x8f4>
    1162:	e8 29 f8 ff ff       	callq  990 <puts@plt>
    1167:	48 8d 3d d6 01 00 00 	lea    0x1d6(%rip),%rdi        # 1344 <__cxa_finalize@plt+0x904>
    116e:	e8 1d f8 ff ff       	callq  990 <puts@plt>
    1173:	5d                   	pop    %rbp
    1174:	c3                   	retq   
    1175:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    117c:	00 00 00 
    117f:	90                   	nop
    1180:	41 57                	push   %r15
    1182:	41 89 ff             	mov    %edi,%r15d
    1185:	41 56                	push   %r14
    1187:	49 89 f6             	mov    %rsi,%r14
    118a:	41 55                	push   %r13
    118c:	49 89 d5             	mov    %rdx,%r13
    118f:	41 54                	push   %r12
    1191:	4c 8d 25 40 0c 20 00 	lea    0x200c40(%rip),%r12        # 201dd8 <__cxa_finalize@plt+0x201398>
    1198:	55                   	push   %rbp
    1199:	48 8d 2d 40 0c 20 00 	lea    0x200c40(%rip),%rbp        # 201de0 <__cxa_finalize@plt+0x2013a0>
    11a0:	53                   	push   %rbx
    11a1:	4c 29 e5             	sub    %r12,%rbp
    11a4:	31 db                	xor    %ebx,%ebx
    11a6:	48 c1 fd 03          	sar    $0x3,%rbp
    11aa:	48 83 ec 08          	sub    $0x8,%rsp
    11ae:	e8 7d f7 ff ff       	callq  930 <free@plt-0x30>
    11b3:	48 85 ed             	test   %rbp,%rbp
    11b6:	74 1e                	je     11d6 <__cxa_finalize@plt+0x796>
    11b8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    11bf:	00 
    11c0:	4c 89 ea             	mov    %r13,%rdx
    11c3:	4c 89 f6             	mov    %r14,%rsi
    11c6:	44 89 ff             	mov    %r15d,%edi
    11c9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
    11cd:	48 83 c3 01          	add    $0x1,%rbx
    11d1:	48 39 eb             	cmp    %rbp,%rbx
    11d4:	75 ea                	jne    11c0 <__cxa_finalize@plt+0x780>
    11d6:	48 83 c4 08          	add    $0x8,%rsp
    11da:	5b                   	pop    %rbx
    11db:	5d                   	pop    %rbp
    11dc:	41 5c                	pop    %r12
    11de:	41 5d                	pop    %r13
    11e0:	41 5e                	pop    %r14
    11e2:	41 5f                	pop    %r15
    11e4:	c3                   	retq   
    11e5:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    11ec:	00 00 00 00 
    11f0:	f3 c3                	repz retq 

Disassembly of section .fini:

00000000000011f4 <.fini>:
    11f4:	48 83 ec 08          	sub    $0x8,%rsp
    11f8:	48 83 c4 08          	add    $0x8,%rsp
    11fc:	c3                   	retq   
