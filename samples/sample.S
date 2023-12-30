
sample:     file format elf64-x86-64


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
    1020:	ff 35 8a 2f 00 00    	pushq  0x2f8a(%rip)        # 3fb0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 8b 2f 00 00 	bnd jmpq *0x2f8b(%rip)        # 3fb8 <_GLOBAL_OFFSET_TABLE_+0x10>
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

Disassembly of section .plt.got:

0000000000001060 <__cxa_finalize@plt>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	f2 ff 25 8d 2f 00 00 	bnd jmpq *0x2f8d(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    106b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001070 <putchar@plt>:
    1070:	f3 0f 1e fa          	endbr64 
    1074:	f2 ff 25 45 2f 00 00 	bnd jmpq *0x2f45(%rip)        # 3fc0 <putchar@GLIBC_2.2.5>
    107b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001080 <__stack_chk_fail@plt>:
    1080:	f3 0f 1e fa          	endbr64 
    1084:	f2 ff 25 3d 2f 00 00 	bnd jmpq *0x2f3d(%rip)        # 3fc8 <__stack_chk_fail@GLIBC_2.4>
    108b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001090 <printf@plt>:
    1090:	f3 0f 1e fa          	endbr64 
    1094:	f2 ff 25 35 2f 00 00 	bnd jmpq *0x2f35(%rip)        # 3fd0 <printf@GLIBC_2.2.5>
    109b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

00000000000010a0 <_start>:
    10a0:	f3 0f 1e fa          	endbr64 
    10a4:	31 ed                	xor    %ebp,%ebp
    10a6:	49 89 d1             	mov    %rdx,%r9
    10a9:	5e                   	pop    %rsi
    10aa:	48 89 e2             	mov    %rsp,%rdx
    10ad:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    10b1:	50                   	push   %rax
    10b2:	54                   	push   %rsp
    10b3:	4c 8d 05 76 03 00 00 	lea    0x376(%rip),%r8        # 1430 <__libc_csu_fini>
    10ba:	48 8d 0d ff 02 00 00 	lea    0x2ff(%rip),%rcx        # 13c0 <__libc_csu_init>
    10c1:	48 8d 3d 1e 02 00 00 	lea    0x21e(%rip),%rdi        # 12e6 <main>
    10c8:	ff 15 12 2f 00 00    	callq  *0x2f12(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    10ce:	f4                   	hlt    
    10cf:	90                   	nop

00000000000010d0 <deregister_tm_clones>:
    10d0:	48 8d 3d 39 2f 00 00 	lea    0x2f39(%rip),%rdi        # 4010 <__TMC_END__>
    10d7:	48 8d 05 32 2f 00 00 	lea    0x2f32(%rip),%rax        # 4010 <__TMC_END__>
    10de:	48 39 f8             	cmp    %rdi,%rax
    10e1:	74 15                	je     10f8 <deregister_tm_clones+0x28>
    10e3:	48 8b 05 ee 2e 00 00 	mov    0x2eee(%rip),%rax        # 3fd8 <_ITM_deregisterTMCloneTable>
    10ea:	48 85 c0             	test   %rax,%rax
    10ed:	74 09                	je     10f8 <deregister_tm_clones+0x28>
    10ef:	ff e0                	jmpq   *%rax
    10f1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10f8:	c3                   	retq   
    10f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001100 <register_tm_clones>:
    1100:	48 8d 3d 09 2f 00 00 	lea    0x2f09(%rip),%rdi        # 4010 <__TMC_END__>
    1107:	48 8d 35 02 2f 00 00 	lea    0x2f02(%rip),%rsi        # 4010 <__TMC_END__>
    110e:	48 29 fe             	sub    %rdi,%rsi
    1111:	48 89 f0             	mov    %rsi,%rax
    1114:	48 c1 ee 3f          	shr    $0x3f,%rsi
    1118:	48 c1 f8 03          	sar    $0x3,%rax
    111c:	48 01 c6             	add    %rax,%rsi
    111f:	48 d1 fe             	sar    %rsi
    1122:	74 14                	je     1138 <register_tm_clones+0x38>
    1124:	48 8b 05 c5 2e 00 00 	mov    0x2ec5(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable>
    112b:	48 85 c0             	test   %rax,%rax
    112e:	74 08                	je     1138 <register_tm_clones+0x38>
    1130:	ff e0                	jmpq   *%rax
    1132:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1138:	c3                   	retq   
    1139:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001140 <__do_global_dtors_aux>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	80 3d c5 2e 00 00 00 	cmpb   $0x0,0x2ec5(%rip)        # 4010 <__TMC_END__>
    114b:	75 2b                	jne    1178 <__do_global_dtors_aux+0x38>
    114d:	55                   	push   %rbp
    114e:	48 83 3d a2 2e 00 00 	cmpq   $0x0,0x2ea2(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1155:	00 
    1156:	48 89 e5             	mov    %rsp,%rbp
    1159:	74 0c                	je     1167 <__do_global_dtors_aux+0x27>
    115b:	48 8b 3d a6 2e 00 00 	mov    0x2ea6(%rip),%rdi        # 4008 <__dso_handle>
    1162:	e8 f9 fe ff ff       	callq  1060 <__cxa_finalize@plt>
    1167:	e8 64 ff ff ff       	callq  10d0 <deregister_tm_clones>
    116c:	c6 05 9d 2e 00 00 01 	movb   $0x1,0x2e9d(%rip)        # 4010 <__TMC_END__>
    1173:	5d                   	pop    %rbp
    1174:	c3                   	retq   
    1175:	0f 1f 00             	nopl   (%rax)
    1178:	c3                   	retq   
    1179:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001180 <frame_dummy>:
    1180:	f3 0f 1e fa          	endbr64 
    1184:	e9 77 ff ff ff       	jmpq   1100 <register_tm_clones>

0000000000001189 <callee>:
    1189:	f3 0f 1e fa          	endbr64 
    118d:	55                   	push   %rbp
    118e:	48 89 e5             	mov    %rsp,%rbp
    1191:	48 83 ec 40          	sub    $0x40,%rsp
    1195:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1199:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    119c:	48 89 d0             	mov    %rdx,%rax
    119f:	48 89 ca             	mov    %rcx,%rdx
    11a2:	4c 89 45 c8          	mov    %r8,-0x38(%rbp)
    11a6:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    11aa:	8b 45 d8             	mov    -0x28(%rbp),%eax
    11ad:	83 e0 00             	and    $0x0,%eax
    11b0:	09 d0                	or     %edx,%eax
    11b2:	89 45 d8             	mov    %eax,-0x28(%rbp)
    11b5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    11b9:	48 89 c6             	mov    %rax,%rsi
    11bc:	48 8d 3d 45 0e 00 00 	lea    0xe45(%rip),%rdi        # 2008 <_IO_stdin_used+0x8>
    11c3:	b8 00 00 00 00       	mov    $0x0,%eax
    11c8:	e8 c3 fe ff ff       	callq  1090 <printf@plt>
    11cd:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    11d0:	89 c6                	mov    %eax,%esi
    11d2:	48 8d 3d 32 0e 00 00 	lea    0xe32(%rip),%rdi        # 200b <_IO_stdin_used+0xb>
    11d9:	b8 00 00 00 00       	mov    $0x0,%eax
    11de:	e8 ad fe ff ff       	callq  1090 <printf@plt>
    11e3:	0f b6 45 d4          	movzbl -0x2c(%rbp),%eax
    11e7:	0f b6 c0             	movzbl %al,%eax
    11ea:	89 c6                	mov    %eax,%esi
    11ec:	48 8d 3d 2a 0e 00 00 	lea    0xe2a(%rip),%rdi        # 201d <_IO_stdin_used+0x1d>
    11f3:	b8 00 00 00 00       	mov    $0x0,%eax
    11f8:	e8 93 fe ff ff       	callq  1090 <printf@plt>
    11fd:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    1204:	eb 2d                	jmp    1233 <callee+0xaa>
    1206:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1209:	48 98                	cltq   
    120b:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    1212:	00 
    1213:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    1217:	48 01 d0             	add    %rdx,%rax
    121a:	8b 00                	mov    (%rax),%eax
    121c:	89 c6                	mov    %eax,%esi
    121e:	48 8d 3d 12 0e 00 00 	lea    0xe12(%rip),%rdi        # 2037 <_IO_stdin_used+0x37>
    1225:	b8 00 00 00 00       	mov    $0x0,%eax
    122a:	e8 61 fe ff ff       	callq  1090 <printf@plt>
    122f:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    1233:	83 7d fc 02          	cmpl   $0x2,-0x4(%rbp)
    1237:	7e cd                	jle    1206 <callee+0x7d>
    1239:	bf 0a 00 00 00       	mov    $0xa,%edi
    123e:	e8 2d fe ff ff       	callq  1070 <putchar@plt>
    1243:	90                   	nop
    1244:	c9                   	leaveq 
    1245:	c3                   	retq   

0000000000001246 <callee2>:
    1246:	f3 0f 1e fa          	endbr64 
    124a:	55                   	push   %rbp
    124b:	48 89 e5             	mov    %rsp,%rbp
    124e:	48 83 ec 20          	sub    $0x20,%rsp
    1252:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    1256:	89 75 f4             	mov    %esi,-0xc(%rbp)
    1259:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    125d:	89 c8                	mov    %ecx,%eax
    125f:	88 45 f0             	mov    %al,-0x10(%rbp)
    1262:	0f be 75 f0          	movsbl -0x10(%rbp),%esi
    1266:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    126a:	8b 55 f4             	mov    -0xc(%rbp),%edx
    126d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1271:	41 89 f0             	mov    %esi,%r8d
    1274:	48 89 c6             	mov    %rax,%rsi
    1277:	48 8d 3d c2 0d 00 00 	lea    0xdc2(%rip),%rdi        # 2040 <_IO_stdin_used+0x40>
    127e:	b8 00 00 00 00       	mov    $0x0,%eax
    1283:	e8 08 fe ff ff       	callq  1090 <printf@plt>
    1288:	90                   	nop
    1289:	c9                   	leaveq 
    128a:	c3                   	retq   

000000000000128b <dump_pointed_val_of>:
    128b:	f3 0f 1e fa          	endbr64 
    128f:	55                   	push   %rbp
    1290:	48 89 e5             	mov    %rsp,%rbp
    1293:	48 83 ec 10          	sub    $0x10,%rsp
    1297:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    129b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    129f:	8b 00                	mov    (%rax),%eax
    12a1:	89 c6                	mov    %eax,%esi
    12a3:	48 8d 3d c1 0d 00 00 	lea    0xdc1(%rip),%rdi        # 206b <_IO_stdin_used+0x6b>
    12aa:	b8 00 00 00 00       	mov    $0x0,%eax
    12af:	e8 dc fd ff ff       	callq  1090 <printf@plt>
    12b4:	90                   	nop
    12b5:	c9                   	leaveq 
    12b6:	c3                   	retq   

00000000000012b7 <dump_pointed_twice>:
    12b7:	f3 0f 1e fa          	endbr64 
    12bb:	55                   	push   %rbp
    12bc:	48 89 e5             	mov    %rsp,%rbp
    12bf:	48 83 ec 10          	sub    $0x10,%rsp
    12c3:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    12c7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    12cb:	48 8b 00             	mov    (%rax),%rax
    12ce:	8b 00                	mov    (%rax),%eax
    12d0:	89 c6                	mov    %eax,%esi
    12d2:	48 8d 3d a4 0d 00 00 	lea    0xda4(%rip),%rdi        # 207d <_IO_stdin_used+0x7d>
    12d9:	b8 00 00 00 00       	mov    $0x0,%eax
    12de:	e8 ad fd ff ff       	callq  1090 <printf@plt>
    12e3:	90                   	nop
    12e4:	c9                   	leaveq 
    12e5:	c3                   	retq   

00000000000012e6 <main>:
    12e6:	f3 0f 1e fa          	endbr64 
    12ea:	55                   	push   %rbp
    12eb:	48 89 e5             	mov    %rsp,%rbp
    12ee:	48 83 ec 40          	sub    $0x40,%rsp
    12f2:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    12f9:	00 00 
    12fb:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    12ff:	31 c0                	xor    %eax,%eax
    1301:	c7 45 ec 01 00 00 00 	movl   $0x1,-0x14(%rbp)
    1308:	c7 45 f0 02 00 00 00 	movl   $0x2,-0x10(%rbp)
    130f:	c7 45 f4 03 00 00 00 	movl   $0x3,-0xc(%rbp)
    1316:	c7 45 e0 14 00 00 00 	movl   $0x14,-0x20(%rbp)
    131d:	c6 45 e4 01          	movb   $0x1,-0x1c(%rbp)
    1321:	c7 45 e8 32 00 00 00 	movl   $0x32,-0x18(%rbp)
    1328:	48 8d 75 ec          	lea    -0x14(%rbp),%rsi
    132c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1330:	8b 4d e8             	mov    -0x18(%rbp),%ecx
    1333:	48 89 ca             	mov    %rcx,%rdx
    1336:	49 89 f0             	mov    %rsi,%r8
    1339:	48 89 d1             	mov    %rdx,%rcx
    133c:	48 89 c2             	mov    %rax,%rdx
    133f:	be 63 00 00 00       	mov    $0x63,%esi
    1344:	48 8d 3d 36 0d 00 00 	lea    0xd36(%rip),%rdi        # 2081 <_IO_stdin_used+0x81>
    134b:	e8 39 fe ff ff       	callq  1189 <callee>
    1350:	b9 41 00 00 00       	mov    $0x41,%ecx
    1355:	ba 34 00 00 00       	mov    $0x34,%edx
    135a:	be 10 00 00 00       	mov    $0x10,%esi
    135f:	48 bf 00 50 39 27 8c 	movabs $0x48c27395000,%rdi
    1366:	04 00 00 
    1369:	e8 d8 fe ff ff       	callq  1246 <callee2>
    136e:	c7 45 cc 05 00 00 00 	movl   $0x5,-0x34(%rbp)
    1375:	48 8d 45 cc          	lea    -0x34(%rbp),%rax
    1379:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    137d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    1381:	48 89 c7             	mov    %rax,%rdi
    1384:	e8 02 ff ff ff       	callq  128b <dump_pointed_val_of>
    1389:	48 8d 45 d0          	lea    -0x30(%rbp),%rax
    138d:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    1391:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1395:	48 89 c7             	mov    %rax,%rdi
    1398:	e8 1a ff ff ff       	callq  12b7 <dump_pointed_twice>
    139d:	b8 00 00 00 00       	mov    $0x0,%eax
    13a2:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    13a6:	64 48 33 14 25 28 00 	xor    %fs:0x28,%rdx
    13ad:	00 00 
    13af:	74 05                	je     13b6 <main+0xd0>
    13b1:	e8 ca fc ff ff       	callq  1080 <__stack_chk_fail@plt>
    13b6:	c9                   	leaveq 
    13b7:	c3                   	retq   
    13b8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    13bf:	00 

00000000000013c0 <__libc_csu_init>:
    13c0:	f3 0f 1e fa          	endbr64 
    13c4:	41 57                	push   %r15
    13c6:	4c 8d 3d db 29 00 00 	lea    0x29db(%rip),%r15        # 3da8 <__frame_dummy_init_array_entry>
    13cd:	41 56                	push   %r14
    13cf:	49 89 d6             	mov    %rdx,%r14
    13d2:	41 55                	push   %r13
    13d4:	49 89 f5             	mov    %rsi,%r13
    13d7:	41 54                	push   %r12
    13d9:	41 89 fc             	mov    %edi,%r12d
    13dc:	55                   	push   %rbp
    13dd:	48 8d 2d cc 29 00 00 	lea    0x29cc(%rip),%rbp        # 3db0 <__do_global_dtors_aux_fini_array_entry>
    13e4:	53                   	push   %rbx
    13e5:	4c 29 fd             	sub    %r15,%rbp
    13e8:	48 83 ec 08          	sub    $0x8,%rsp
    13ec:	e8 0f fc ff ff       	callq  1000 <_init>
    13f1:	48 c1 fd 03          	sar    $0x3,%rbp
    13f5:	74 1f                	je     1416 <__libc_csu_init+0x56>
    13f7:	31 db                	xor    %ebx,%ebx
    13f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1400:	4c 89 f2             	mov    %r14,%rdx
    1403:	4c 89 ee             	mov    %r13,%rsi
    1406:	44 89 e7             	mov    %r12d,%edi
    1409:	41 ff 14 df          	callq  *(%r15,%rbx,8)
    140d:	48 83 c3 01          	add    $0x1,%rbx
    1411:	48 39 dd             	cmp    %rbx,%rbp
    1414:	75 ea                	jne    1400 <__libc_csu_init+0x40>
    1416:	48 83 c4 08          	add    $0x8,%rsp
    141a:	5b                   	pop    %rbx
    141b:	5d                   	pop    %rbp
    141c:	41 5c                	pop    %r12
    141e:	41 5d                	pop    %r13
    1420:	41 5e                	pop    %r14
    1422:	41 5f                	pop    %r15
    1424:	c3                   	retq   
    1425:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    142c:	00 00 00 00 

0000000000001430 <__libc_csu_fini>:
    1430:	f3 0f 1e fa          	endbr64 
    1434:	c3                   	retq   

Disassembly of section .fini:

0000000000001438 <_fini>:
    1438:	f3 0f 1e fa          	endbr64 
    143c:	48 83 ec 08          	sub    $0x8,%rsp
    1440:	48 83 c4 08          	add    $0x8,%rsp
    1444:	c3                   	retq   
