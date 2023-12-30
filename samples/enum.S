
enum:     file format elf64-x86-64


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
    1020:	ff 35 9a 2f 00 00    	pushq  0x2f9a(%rip)        # 3fc0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 9b 2f 00 00 	bnd jmpq *0x2f9b(%rip)        # 3fc8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nopl   (%rax)
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	pushq  $0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmpq 1020 <.plt>
    103f:	90                   	nop

Disassembly of section .plt.got:

0000000000001040 <__cxa_finalize@plt>:
    1040:	f3 0f 1e fa          	endbr64 
    1044:	f2 ff 25 ad 2f 00 00 	bnd jmpq *0x2fad(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    104b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001050 <puts@plt>:
    1050:	f3 0f 1e fa          	endbr64 
    1054:	f2 ff 25 75 2f 00 00 	bnd jmpq *0x2f75(%rip)        # 3fd0 <puts@GLIBC_2.2.5>
    105b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001060 <_start>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	31 ed                	xor    %ebp,%ebp
    1066:	49 89 d1             	mov    %rdx,%r9
    1069:	5e                   	pop    %rsi
    106a:	48 89 e2             	mov    %rsp,%rdx
    106d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1071:	50                   	push   %rax
    1072:	54                   	push   %rsp
    1073:	4c 8d 05 c6 01 00 00 	lea    0x1c6(%rip),%r8        # 1240 <__libc_csu_fini>
    107a:	48 8d 0d 4f 01 00 00 	lea    0x14f(%rip),%rcx        # 11d0 <__libc_csu_init>
    1081:	48 8d 3d 24 01 00 00 	lea    0x124(%rip),%rdi        # 11ac <main>
    1088:	ff 15 52 2f 00 00    	callq  *0x2f52(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    108e:	f4                   	hlt    
    108f:	90                   	nop

0000000000001090 <deregister_tm_clones>:
    1090:	48 8d 3d 79 2f 00 00 	lea    0x2f79(%rip),%rdi        # 4010 <__TMC_END__>
    1097:	48 8d 05 72 2f 00 00 	lea    0x2f72(%rip),%rax        # 4010 <__TMC_END__>
    109e:	48 39 f8             	cmp    %rdi,%rax
    10a1:	74 15                	je     10b8 <deregister_tm_clones+0x28>
    10a3:	48 8b 05 2e 2f 00 00 	mov    0x2f2e(%rip),%rax        # 3fd8 <_ITM_deregisterTMCloneTable>
    10aa:	48 85 c0             	test   %rax,%rax
    10ad:	74 09                	je     10b8 <deregister_tm_clones+0x28>
    10af:	ff e0                	jmpq   *%rax
    10b1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10b8:	c3                   	retq   
    10b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000010c0 <register_tm_clones>:
    10c0:	48 8d 3d 49 2f 00 00 	lea    0x2f49(%rip),%rdi        # 4010 <__TMC_END__>
    10c7:	48 8d 35 42 2f 00 00 	lea    0x2f42(%rip),%rsi        # 4010 <__TMC_END__>
    10ce:	48 29 fe             	sub    %rdi,%rsi
    10d1:	48 89 f0             	mov    %rsi,%rax
    10d4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    10d8:	48 c1 f8 03          	sar    $0x3,%rax
    10dc:	48 01 c6             	add    %rax,%rsi
    10df:	48 d1 fe             	sar    %rsi
    10e2:	74 14                	je     10f8 <register_tm_clones+0x38>
    10e4:	48 8b 05 05 2f 00 00 	mov    0x2f05(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable>
    10eb:	48 85 c0             	test   %rax,%rax
    10ee:	74 08                	je     10f8 <register_tm_clones+0x38>
    10f0:	ff e0                	jmpq   *%rax
    10f2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    10f8:	c3                   	retq   
    10f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001100 <__do_global_dtors_aux>:
    1100:	f3 0f 1e fa          	endbr64 
    1104:	80 3d 05 2f 00 00 00 	cmpb   $0x0,0x2f05(%rip)        # 4010 <__TMC_END__>
    110b:	75 2b                	jne    1138 <__do_global_dtors_aux+0x38>
    110d:	55                   	push   %rbp
    110e:	48 83 3d e2 2e 00 00 	cmpq   $0x0,0x2ee2(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1115:	00 
    1116:	48 89 e5             	mov    %rsp,%rbp
    1119:	74 0c                	je     1127 <__do_global_dtors_aux+0x27>
    111b:	48 8b 3d e6 2e 00 00 	mov    0x2ee6(%rip),%rdi        # 4008 <__dso_handle>
    1122:	e8 19 ff ff ff       	callq  1040 <__cxa_finalize@plt>
    1127:	e8 64 ff ff ff       	callq  1090 <deregister_tm_clones>
    112c:	c6 05 dd 2e 00 00 01 	movb   $0x1,0x2edd(%rip)        # 4010 <__TMC_END__>
    1133:	5d                   	pop    %rbp
    1134:	c3                   	retq   
    1135:	0f 1f 00             	nopl   (%rax)
    1138:	c3                   	retq   
    1139:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001140 <frame_dummy>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	e9 77 ff ff ff       	jmpq   10c0 <register_tm_clones>

0000000000001149 <printColor>:
    1149:	f3 0f 1e fa          	endbr64 
    114d:	55                   	push   %rbp
    114e:	48 89 e5             	mov    %rsp,%rbp
    1151:	48 83 ec 10          	sub    $0x10,%rsp
    1155:	89 7d fc             	mov    %edi,-0x4(%rbp)
    1158:	83 7d fc 02          	cmpl   $0x2,-0x4(%rbp)
    115c:	74 30                	je     118e <printColor+0x45>
    115e:	83 7d fc 02          	cmpl   $0x2,-0x4(%rbp)
    1162:	77 38                	ja     119c <printColor+0x53>
    1164:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    1168:	74 08                	je     1172 <printColor+0x29>
    116a:	83 7d fc 01          	cmpl   $0x1,-0x4(%rbp)
    116e:	74 10                	je     1180 <printColor+0x37>
    1170:	eb 2a                	jmp    119c <printColor+0x53>
    1172:	48 8d 3d 8b 0e 00 00 	lea    0xe8b(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    1179:	e8 d2 fe ff ff       	callq  1050 <puts@plt>
    117e:	eb 29                	jmp    11a9 <printColor+0x60>
    1180:	48 8d 3d 8a 0e 00 00 	lea    0xe8a(%rip),%rdi        # 2011 <_IO_stdin_used+0x11>
    1187:	e8 c4 fe ff ff       	callq  1050 <puts@plt>
    118c:	eb 1b                	jmp    11a9 <printColor+0x60>
    118e:	48 8d 3d 8b 0e 00 00 	lea    0xe8b(%rip),%rdi        # 2020 <_IO_stdin_used+0x20>
    1195:	e8 b6 fe ff ff       	callq  1050 <puts@plt>
    119a:	eb 0d                	jmp    11a9 <printColor+0x60>
    119c:	48 8d 3d 8b 0e 00 00 	lea    0xe8b(%rip),%rdi        # 202e <_IO_stdin_used+0x2e>
    11a3:	e8 a8 fe ff ff       	callq  1050 <puts@plt>
    11a8:	90                   	nop
    11a9:	90                   	nop
    11aa:	c9                   	leaveq 
    11ab:	c3                   	retq   

00000000000011ac <main>:
    11ac:	f3 0f 1e fa          	endbr64 
    11b0:	55                   	push   %rbp
    11b1:	48 89 e5             	mov    %rsp,%rbp
    11b4:	48 83 ec 10          	sub    $0x10,%rsp
    11b8:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    11bf:	8b 45 fc             	mov    -0x4(%rbp),%eax
    11c2:	89 c7                	mov    %eax,%edi
    11c4:	e8 80 ff ff ff       	callq  1149 <printColor>
    11c9:	b8 00 00 00 00       	mov    $0x0,%eax
    11ce:	c9                   	leaveq 
    11cf:	c3                   	retq   

00000000000011d0 <__libc_csu_init>:
    11d0:	f3 0f 1e fa          	endbr64 
    11d4:	41 57                	push   %r15
    11d6:	4c 8d 3d db 2b 00 00 	lea    0x2bdb(%rip),%r15        # 3db8 <__frame_dummy_init_array_entry>
    11dd:	41 56                	push   %r14
    11df:	49 89 d6             	mov    %rdx,%r14
    11e2:	41 55                	push   %r13
    11e4:	49 89 f5             	mov    %rsi,%r13
    11e7:	41 54                	push   %r12
    11e9:	41 89 fc             	mov    %edi,%r12d
    11ec:	55                   	push   %rbp
    11ed:	48 8d 2d cc 2b 00 00 	lea    0x2bcc(%rip),%rbp        # 3dc0 <__do_global_dtors_aux_fini_array_entry>
    11f4:	53                   	push   %rbx
    11f5:	4c 29 fd             	sub    %r15,%rbp
    11f8:	48 83 ec 08          	sub    $0x8,%rsp
    11fc:	e8 ff fd ff ff       	callq  1000 <_init>
    1201:	48 c1 fd 03          	sar    $0x3,%rbp
    1205:	74 1f                	je     1226 <__libc_csu_init+0x56>
    1207:	31 db                	xor    %ebx,%ebx
    1209:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1210:	4c 89 f2             	mov    %r14,%rdx
    1213:	4c 89 ee             	mov    %r13,%rsi
    1216:	44 89 e7             	mov    %r12d,%edi
    1219:	41 ff 14 df          	callq  *(%r15,%rbx,8)
    121d:	48 83 c3 01          	add    $0x1,%rbx
    1221:	48 39 dd             	cmp    %rbx,%rbp
    1224:	75 ea                	jne    1210 <__libc_csu_init+0x40>
    1226:	48 83 c4 08          	add    $0x8,%rsp
    122a:	5b                   	pop    %rbx
    122b:	5d                   	pop    %rbp
    122c:	41 5c                	pop    %r12
    122e:	41 5d                	pop    %r13
    1230:	41 5e                	pop    %r14
    1232:	41 5f                	pop    %r15
    1234:	c3                   	retq   
    1235:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    123c:	00 00 00 00 

0000000000001240 <__libc_csu_fini>:
    1240:	f3 0f 1e fa          	endbr64 
    1244:	c3                   	retq   

Disassembly of section .fini:

0000000000001248 <_fini>:
    1248:	f3 0f 1e fa          	endbr64 
    124c:	48 83 ec 08          	sub    $0x8,%rsp
    1250:	48 83 c4 08          	add    $0x8,%rsp
    1254:	c3                   	retq   
