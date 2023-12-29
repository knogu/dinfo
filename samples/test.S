
./test:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d9 2f 00 00 	mov    0x2fd9(%rip),%rax        # 3fe8 <__gmon_start__>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	callq  *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	retq   

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 82 2f 00 00    	pushq  0x2f82(%rip)        # 3fa8 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 83 2f 00 00 	bnd jmpq *0x2f83(%rip)        # 3fb0 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nopl   (%rax)
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	pushq  $0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmpq 1020 <.plt>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64 
    1044:	68 01 00 00 00       	pushq  $0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmpq 1020 <.plt>
    104f:	90                   	nop
    1050:	f3 0f 1e fa          	endbr64 
    1054:	68 02 00 00 00       	pushq  $0x2
    1059:	f2 e9 c1 ff ff ff    	bnd jmpq 1020 <.plt>
    105f:	90                   	nop
    1060:	f3 0f 1e fa          	endbr64 
    1064:	68 03 00 00 00       	pushq  $0x3
    1069:	f2 e9 b1 ff ff ff    	bnd jmpq 1020 <.plt>
    106f:	90                   	nop

Disassembly of section .plt.got:

0000000000001070 <__cxa_finalize@plt>:
    1070:	f3 0f 1e fa          	endbr64 
    1074:	f2 ff 25 7d 2f 00 00 	bnd jmpq *0x2f7d(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    107b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001080 <putchar@plt>:
    1080:	f3 0f 1e fa          	endbr64 
    1084:	f2 ff 25 2d 2f 00 00 	bnd jmpq *0x2f2d(%rip)        # 3fb8 <putchar@GLIBC_2.2.5>
    108b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001090 <__cyg_profile_func_enter@plt>:
    1090:	f3 0f 1e fa          	endbr64 
    1094:	f2 ff 25 25 2f 00 00 	bnd jmpq *0x2f25(%rip)        # 3fc0 <__cyg_profile_func_enter>
    109b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000010a0 <printf@plt>:
    10a0:	f3 0f 1e fa          	endbr64 
    10a4:	f2 ff 25 1d 2f 00 00 	bnd jmpq *0x2f1d(%rip)        # 3fc8 <printf@GLIBC_2.2.5>
    10ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000010b0 <__cyg_profile_func_exit@plt>:
    10b0:	f3 0f 1e fa          	endbr64 
    10b4:	f2 ff 25 15 2f 00 00 	bnd jmpq *0x2f15(%rip)        # 3fd0 <__cyg_profile_func_exit>
    10bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

00000000000010c0 <_start>:
    10c0:	f3 0f 1e fa          	endbr64 
    10c4:	31 ed                	xor    %ebp,%ebp
    10c6:	49 89 d1             	mov    %rdx,%r9
    10c9:	5e                   	pop    %rsi
    10ca:	48 89 e2             	mov    %rsp,%rdx
    10cd:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    10d1:	50                   	push   %rax
    10d2:	54                   	push   %rsp
    10d3:	4c 8d 05 b6 02 00 00 	lea    0x2b6(%rip),%r8        # 1390 <__libc_csu_fini>
    10da:	48 8d 0d 3f 02 00 00 	lea    0x23f(%rip),%rcx        # 1320 <__libc_csu_init>
    10e1:	48 8d 3d e1 01 00 00 	lea    0x1e1(%rip),%rdi        # 12c9 <main>
    10e8:	ff 15 f2 2e 00 00    	callq  *0x2ef2(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    10ee:	f4                   	hlt    
    10ef:	90                   	nop

00000000000010f0 <deregister_tm_clones>:
    10f0:	48 8d 3d 19 2f 00 00 	lea    0x2f19(%rip),%rdi        # 4010 <__TMC_END__>
    10f7:	48 8d 05 12 2f 00 00 	lea    0x2f12(%rip),%rax        # 4010 <__TMC_END__>
    10fe:	48 39 f8             	cmp    %rdi,%rax
    1101:	74 15                	je     1118 <deregister_tm_clones+0x28>
    1103:	48 8b 05 ce 2e 00 00 	mov    0x2ece(%rip),%rax        # 3fd8 <_ITM_deregisterTMCloneTable>
    110a:	48 85 c0             	test   %rax,%rax
    110d:	74 09                	je     1118 <deregister_tm_clones+0x28>
    110f:	ff e0                	jmpq   *%rax
    1111:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1118:	c3                   	retq   
    1119:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001120 <register_tm_clones>:
    1120:	48 8d 3d e9 2e 00 00 	lea    0x2ee9(%rip),%rdi        # 4010 <__TMC_END__>
    1127:	48 8d 35 e2 2e 00 00 	lea    0x2ee2(%rip),%rsi        # 4010 <__TMC_END__>
    112e:	48 29 fe             	sub    %rdi,%rsi
    1131:	48 89 f0             	mov    %rsi,%rax
    1134:	48 c1 ee 3f          	shr    $0x3f,%rsi
    1138:	48 c1 f8 03          	sar    $0x3,%rax
    113c:	48 01 c6             	add    %rax,%rsi
    113f:	48 d1 fe             	sar    %rsi
    1142:	74 14                	je     1158 <register_tm_clones+0x38>
    1144:	48 8b 05 a5 2e 00 00 	mov    0x2ea5(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable>
    114b:	48 85 c0             	test   %rax,%rax
    114e:	74 08                	je     1158 <register_tm_clones+0x38>
    1150:	ff e0                	jmpq   *%rax
    1152:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1158:	c3                   	retq   
    1159:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001160 <__do_global_dtors_aux>:
    1160:	f3 0f 1e fa          	endbr64 
    1164:	80 3d a5 2e 00 00 00 	cmpb   $0x0,0x2ea5(%rip)        # 4010 <__TMC_END__>
    116b:	75 2b                	jne    1198 <__do_global_dtors_aux+0x38>
    116d:	55                   	push   %rbp
    116e:	48 83 3d 82 2e 00 00 	cmpq   $0x0,0x2e82(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1175:	00 
    1176:	48 89 e5             	mov    %rsp,%rbp
    1179:	74 0c                	je     1187 <__do_global_dtors_aux+0x27>
    117b:	48 8b 3d 86 2e 00 00 	mov    0x2e86(%rip),%rdi        # 4008 <__dso_handle>
    1182:	e8 e9 fe ff ff       	callq  1070 <__cxa_finalize@plt>
    1187:	e8 64 ff ff ff       	callq  10f0 <deregister_tm_clones>
    118c:	c6 05 7d 2e 00 00 01 	movb   $0x1,0x2e7d(%rip)        # 4010 <__TMC_END__>
    1193:	5d                   	pop    %rbp
    1194:	c3                   	retq   
    1195:	0f 1f 00             	nopl   (%rax)
    1198:	c3                   	retq   
    1199:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000011a0 <frame_dummy>:
    11a0:	f3 0f 1e fa          	endbr64 
    11a4:	e9 77 ff ff ff       	jmpq   1120 <register_tm_clones>

00000000000011a9 <callee>:
    11a9:	f3 0f 1e fa          	endbr64 
    11ad:	55                   	push   %rbp
    11ae:	48 89 e5             	mov    %rsp,%rbp
    11b1:	48 83 ec 30          	sub    $0x30,%rsp
    11b5:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    11b9:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    11bc:	48 89 55 dc          	mov    %rdx,-0x24(%rbp)
    11c0:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    11c4:	48 8b 45 08          	mov    0x8(%rbp),%rax
    11c8:	48 89 c6             	mov    %rax,%rsi
    11cb:	48 8d 3d d7 ff ff ff 	lea    -0x29(%rip),%rdi        # 11a9 <callee>
    11d2:	e8 b9 fe ff ff       	callq  1090 <__cyg_profile_func_enter@plt>
    11d7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    11db:	48 89 c6             	mov    %rax,%rsi
    11de:	48 8d 3d 1f 0e 00 00 	lea    0xe1f(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    11e5:	b8 00 00 00 00       	mov    $0x0,%eax
    11ea:	e8 b1 fe ff ff       	callq  10a0 <printf@plt>
    11ef:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    11f2:	89 c6                	mov    %eax,%esi
    11f4:	48 8d 3d 0c 0e 00 00 	lea    0xe0c(%rip),%rdi        # 2007 <_IO_stdin_used+0x7>
    11fb:	b8 00 00 00 00       	mov    $0x0,%eax
    1200:	e8 9b fe ff ff       	callq  10a0 <printf@plt>
    1205:	0f b6 45 e0          	movzbl -0x20(%rbp),%eax
    1209:	0f b6 c0             	movzbl %al,%eax
    120c:	89 c6                	mov    %eax,%esi
    120e:	48 8d 3d 04 0e 00 00 	lea    0xe04(%rip),%rdi        # 2019 <_IO_stdin_used+0x19>
    1215:	b8 00 00 00 00       	mov    $0x0,%eax
    121a:	e8 81 fe ff ff       	callq  10a0 <printf@plt>
    121f:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    1226:	eb 2d                	jmp    1255 <callee+0xac>
    1228:	8b 45 fc             	mov    -0x4(%rbp),%eax
    122b:	48 98                	cltq   
    122d:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    1234:	00 
    1235:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1239:	48 01 d0             	add    %rdx,%rax
    123c:	8b 00                	mov    (%rax),%eax
    123e:	89 c6                	mov    %eax,%esi
    1240:	48 8d 3d ec 0d 00 00 	lea    0xdec(%rip),%rdi        # 2033 <_IO_stdin_used+0x33>
    1247:	b8 00 00 00 00       	mov    $0x0,%eax
    124c:	e8 4f fe ff ff       	callq  10a0 <printf@plt>
    1251:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    1255:	83 7d fc 02          	cmpl   $0x2,-0x4(%rbp)
    1259:	7e cd                	jle    1228 <callee+0x7f>
    125b:	bf 0a 00 00 00       	mov    $0xa,%edi
    1260:	e8 1b fe ff ff       	callq  1080 <putchar@plt>
    1265:	48 8b 45 08          	mov    0x8(%rbp),%rax
    1269:	48 89 c6             	mov    %rax,%rsi
    126c:	48 8d 3d 36 ff ff ff 	lea    -0xca(%rip),%rdi        # 11a9 <callee>
    1273:	e8 38 fe ff ff       	callq  10b0 <__cyg_profile_func_exit@plt>
    1278:	90                   	nop
    1279:	c9                   	leaveq 
    127a:	c3                   	retq   

000000000000127b <callee2>:
    127b:	f3 0f 1e fa          	endbr64 
    127f:	55                   	push   %rbp
    1280:	48 89 e5             	mov    %rsp,%rbp
    1283:	48 83 ec 10          	sub    $0x10,%rsp
    1287:	89 7d fc             	mov    %edi,-0x4(%rbp)
    128a:	48 8b 45 08          	mov    0x8(%rbp),%rax
    128e:	48 89 c6             	mov    %rax,%rsi
    1291:	48 8d 3d e3 ff ff ff 	lea    -0x1d(%rip),%rdi        # 127b <callee2>
    1298:	e8 f3 fd ff ff       	callq  1090 <__cyg_profile_func_enter@plt>
    129d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    12a0:	89 c6                	mov    %eax,%esi
    12a2:	48 8d 3d 8e 0d 00 00 	lea    0xd8e(%rip),%rdi        # 2037 <_IO_stdin_used+0x37>
    12a9:	b8 00 00 00 00       	mov    $0x0,%eax
    12ae:	e8 ed fd ff ff       	callq  10a0 <printf@plt>
    12b3:	48 8b 45 08          	mov    0x8(%rbp),%rax
    12b7:	48 89 c6             	mov    %rax,%rsi
    12ba:	48 8d 3d ba ff ff ff 	lea    -0x46(%rip),%rdi        # 127b <callee2>
    12c1:	e8 ea fd ff ff       	callq  10b0 <__cyg_profile_func_exit@plt>
    12c6:	90                   	nop
    12c7:	c9                   	leaveq 
    12c8:	c3                   	retq   

00000000000012c9 <main>:
    12c9:	f3 0f 1e fa          	endbr64 
    12cd:	55                   	push   %rbp
    12ce:	48 89 e5             	mov    %rsp,%rbp
    12d1:	53                   	push   %rbx
    12d2:	48 83 ec 08          	sub    $0x8,%rsp
    12d6:	48 8b 45 08          	mov    0x8(%rbp),%rax
    12da:	48 89 c6             	mov    %rax,%rsi
    12dd:	48 8d 3d e5 ff ff ff 	lea    -0x1b(%rip),%rdi        # 12c9 <main>
    12e4:	e8 a7 fd ff ff       	callq  1090 <__cyg_profile_func_enter@plt>
    12e9:	bf 07 00 00 00       	mov    $0x7,%edi
    12ee:	e8 88 ff ff ff       	callq  127b <callee2>
    12f3:	bb 00 00 00 00       	mov    $0x0,%ebx
    12f8:	48 8b 45 08          	mov    0x8(%rbp),%rax
    12fc:	48 89 c6             	mov    %rax,%rsi
    12ff:	48 8d 3d c3 ff ff ff 	lea    -0x3d(%rip),%rdi        # 12c9 <main>
    1306:	e8 a5 fd ff ff       	callq  10b0 <__cyg_profile_func_exit@plt>
    130b:	89 d8                	mov    %ebx,%eax
    130d:	48 83 c4 08          	add    $0x8,%rsp
    1311:	5b                   	pop    %rbx
    1312:	5d                   	pop    %rbp
    1313:	c3                   	retq   
    1314:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    131b:	00 00 00 
    131e:	66 90                	xchg   %ax,%ax

0000000000001320 <__libc_csu_init>:
    1320:	f3 0f 1e fa          	endbr64 
    1324:	41 57                	push   %r15
    1326:	4c 8d 3d 53 2a 00 00 	lea    0x2a53(%rip),%r15        # 3d80 <__frame_dummy_init_array_entry>
    132d:	41 56                	push   %r14
    132f:	49 89 d6             	mov    %rdx,%r14
    1332:	41 55                	push   %r13
    1334:	49 89 f5             	mov    %rsi,%r13
    1337:	41 54                	push   %r12
    1339:	41 89 fc             	mov    %edi,%r12d
    133c:	55                   	push   %rbp
    133d:	48 8d 2d 44 2a 00 00 	lea    0x2a44(%rip),%rbp        # 3d88 <__do_global_dtors_aux_fini_array_entry>
    1344:	53                   	push   %rbx
    1345:	4c 29 fd             	sub    %r15,%rbp
    1348:	48 83 ec 08          	sub    $0x8,%rsp
    134c:	e8 af fc ff ff       	callq  1000 <_init>
    1351:	48 c1 fd 03          	sar    $0x3,%rbp
    1355:	74 1f                	je     1376 <__libc_csu_init+0x56>
    1357:	31 db                	xor    %ebx,%ebx
    1359:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1360:	4c 89 f2             	mov    %r14,%rdx
    1363:	4c 89 ee             	mov    %r13,%rsi
    1366:	44 89 e7             	mov    %r12d,%edi
    1369:	41 ff 14 df          	callq  *(%r15,%rbx,8)
    136d:	48 83 c3 01          	add    $0x1,%rbx
    1371:	48 39 dd             	cmp    %rbx,%rbp
    1374:	75 ea                	jne    1360 <__libc_csu_init+0x40>
    1376:	48 83 c4 08          	add    $0x8,%rsp
    137a:	5b                   	pop    %rbx
    137b:	5d                   	pop    %rbp
    137c:	41 5c                	pop    %r12
    137e:	41 5d                	pop    %r13
    1380:	41 5e                	pop    %r14
    1382:	41 5f                	pop    %r15
    1384:	c3                   	retq   
    1385:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    138c:	00 00 00 00 

0000000000001390 <__libc_csu_fini>:
    1390:	f3 0f 1e fa          	endbr64 
    1394:	c3                   	retq   

Disassembly of section .fini:

0000000000001398 <_fini>:
    1398:	f3 0f 1e fa          	endbr64 
    139c:	48 83 ec 08          	sub    $0x8,%rsp
    13a0:	48 83 c4 08          	add    $0x8,%rsp
    13a4:	c3                   	retq   
