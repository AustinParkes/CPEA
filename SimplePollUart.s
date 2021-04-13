	.cpu arm7tdmi
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 1
	.eabi_attribute 30, 6
	.eabi_attribute 34, 0
	.eabi_attribute 18, 4
	.file	"SimplePollUart.c"
	.text
	.global	USART1
	.data
	.align	2
	.type	USART1, %object
	.size	USART1, 4
USART1:
	.word	1073821696
	.text
	.align	2
	.global	read_DR
	.arch armv4t
	.syntax unified
	.arm
	.fpu softvfp
	.type	read_DR, %function
read_DR:
	@ Function supports interworking.
	@ args = 0, pretend = 0, frame = 8
	@ frame_needed = 1, uses_anonymous_args = 0
	@ link register save eliminated.
	str	fp, [sp, #-4]!
	add	fp, sp, #0
	sub	sp, sp, #12
	ldr	r3, .L2
	ldr	r3, [r3]
	ldr	r3, [r3, #36]
	strb	r3, [fp, #-5]
	nop
	add	sp, fp, #0
	@ sp needed
	ldr	fp, [sp], #4
	bx	lr
.L3:
	.align	2
.L2:
	.word	USART1
	.size	read_DR, .-read_DR
	.align	2
	.global	main
	.syntax unified
	.arm
	.fpu softvfp
	.type	main, %function
main:
	@ Function supports interworking.
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 1, uses_anonymous_args = 0
	push	{fp, lr}
	add	fp, sp, #4
	ldr	r3, .L6
	ldr	r3, [r3]
	mov	r2, #268435456
	str	r2, [r3]
	bl	read_DR
	mov	r3, #0
	mov	r0, r3
	sub	sp, fp, #4
	@ sp needed
	pop	{fp, lr}
	bx	lr
.L7:
	.align	2
.L6:
	.word	USART1
	.size	main, .-main
	.ident	"GCC: (15:9-2019-q4-0ubuntu1) 9.2.1 20191025 (release) [ARM/arm-9-branch revision 277599]"
