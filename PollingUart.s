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
	.file	"PollingUart.c"
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
	.global	USART_Init
	.arch armv4t
	.syntax unified
	.arm
	.fpu softvfp
	.type	USART_Init, %function
USART_Init:
	@ Function supports interworking.
	@ args = 0, pretend = 0, frame = 8
	@ frame_needed = 1, uses_anonymous_args = 0
	@ link register save eliminated.
	str	fp, [sp, #-4]!
	add	fp, sp, #0
	sub	sp, sp, #12
	str	r0, [fp, #-8]
	ldr	r3, [fp, #-8]
	ldr	r3, [r3]
	bic	r2, r3, #1
	ldr	r3, [fp, #-8]
	str	r2, [r3]
	ldr	r3, [fp, #-8]
	ldr	r3, [r3]
	orr	r2, r3, #268435456
	ldr	r3, [fp, #-8]
	str	r2, [r3]
	ldr	r3, [fp, #-8]
	ldr	r3, [r3]
	bic	r2, r3, #4096
	ldr	r3, [fp, #-8]
	str	r2, [r3]
	ldr	r3, [fp, #-8]
	ldr	r3, [r3, #4]
	bic	r2, r3, #12288
	ldr	r3, [fp, #-8]
	str	r2, [r3, #4]
	ldr	r3, [fp, #-8]
	ldr	r3, [r3]
	bic	r2, r3, #1024
	ldr	r3, [fp, #-8]
	str	r2, [r3]
	ldr	r3, [fp, #-8]
	ldr	r3, [r3]
	bic	r2, r3, #32768
	ldr	r3, [fp, #-8]
	str	r2, [r3]
	ldr	r3, [fp, #-8]
	ldr	r2, .L4
	str	r2, [r3, #12]
	ldr	r3, [fp, #-8]
	ldr	r3, [r3]
	orr	r2, r3, #12
	ldr	r3, [fp, #-8]
	str	r2, [r3]
	ldr	r3, [fp, #-8]
	ldr	r3, [r3]
	orr	r2, r3, #1
	ldr	r3, [fp, #-8]
	str	r2, [r3]
	nop
.L2:
	ldr	r3, [fp, #-8]
	ldr	r3, [r3, #28]
	and	r3, r3, #2097152
	cmp	r3, #0
	beq	.L2
	nop
.L3:
	ldr	r3, [fp, #-8]
	ldr	r3, [r3, #28]
	and	r3, r3, #4194304
	cmp	r3, #0
	beq	.L3
	nop
	nop
	add	sp, fp, #0
	@ sp needed
	ldr	fp, [sp], #4
	bx	lr
.L5:
	.align	2
.L4:
	.word	8333
	.size	USART_Init, .-USART_Init
	.align	2
	.global	USART_Read
	.syntax unified
	.arm
	.fpu softvfp
	.type	USART_Read, %function
USART_Read:
	@ Function supports interworking.
	@ args = 0, pretend = 0, frame = 24
	@ frame_needed = 1, uses_anonymous_args = 0
	@ link register save eliminated.
	str	fp, [sp, #-4]!
	add	fp, sp, #0
	sub	sp, sp, #28
	str	r0, [fp, #-16]
	str	r1, [fp, #-20]
	str	r2, [fp, #-24]
	mov	r3, #0
	str	r3, [fp, #-8]
	b	.L7
.L9:
	nop
.L8:
	ldr	r3, [fp, #-16]
	ldr	r3, [r3, #28]
	and	r3, r3, #32
	cmp	r3, #0
	beq	.L8
	ldr	r3, [fp, #-16]
	ldr	r2, [r3, #36]
	ldr	r3, [fp, #-8]
	ldr	r1, [fp, #-20]
	add	r3, r1, r3
	and	r2, r2, #255
	strb	r2, [r3]
	ldr	r3, [fp, #-8]
	add	r3, r3, #1
	str	r3, [fp, #-8]
.L7:
	ldr	r3, [fp, #-8]
	ldr	r2, [fp, #-24]
	cmp	r2, r3
	bhi	.L9
	nop
	nop
	add	sp, fp, #0
	@ sp needed
	ldr	fp, [sp], #4
	bx	lr
	.size	USART_Read, .-USART_Read
	.align	2
	.global	USART_Write
	.syntax unified
	.arm
	.fpu softvfp
	.type	USART_Write, %function
USART_Write:
	@ Function supports interworking.
	@ args = 0, pretend = 0, frame = 24
	@ frame_needed = 1, uses_anonymous_args = 0
	@ link register save eliminated.
	str	fp, [sp, #-4]!
	add	fp, sp, #0
	sub	sp, sp, #28
	str	r0, [fp, #-16]
	str	r1, [fp, #-20]
	str	r2, [fp, #-24]
	mov	r3, #0
	str	r3, [fp, #-8]
	b	.L11
.L13:
	nop
.L12:
	ldr	r3, [fp, #-16]
	ldr	r3, [r3, #28]
	and	r3, r3, #128
	cmp	r3, #0
	beq	.L12
	ldr	r3, [fp, #-8]
	ldr	r2, [fp, #-20]
	add	r3, r2, r3
	ldrb	r3, [r3]	@ zero_extendqisi2
	mov	r2, r3
	ldr	r3, [fp, #-16]
	str	r2, [r3, #40]
	ldr	r3, [fp, #-8]
	add	r3, r3, #1
	str	r3, [fp, #-8]
.L11:
	ldr	r3, [fp, #-8]
	ldr	r2, [fp, #-24]
	cmp	r2, r3
	bhi	.L13
	nop
.L14:
	ldr	r3, [fp, #-16]
	ldr	r3, [r3, #28]
	and	r3, r3, #64
	cmp	r3, #0
	beq	.L14
	ldr	r3, [fp, #-16]
	ldr	r3, [r3, #32]
	orr	r2, r3, #64
	ldr	r3, [fp, #-16]
	str	r2, [r3, #32]
	nop
	add	sp, fp, #0
	@ sp needed
	ldr	fp, [sp], #4
	bx	lr
	.size	USART_Write, .-USART_Write
	.align	2
	.global	main
	.syntax unified
	.arm
	.fpu softvfp
	.type	main, %function
main:
	@ Function supports interworking.
	@ args = 0, pretend = 0, frame = 16
	@ frame_needed = 1, uses_anonymous_args = 0
	push	{fp, lr}
	add	fp, sp, #4
	sub	sp, sp, #16
	ldr	r3, .L17
	ldr	r3, [r3]
	mov	r0, r3
	bl	USART_Init
	ldr	r3, .L17
	ldr	r3, [r3]
	sub	r1, fp, #16
	mov	r2, #10
	mov	r0, r3
	bl	USART_Read
	ldr	r3, .L17
	ldr	r3, [r3]
	sub	r1, fp, #16
	mov	r2, #10
	mov	r0, r3
	bl	USART_Write
	mov	r3, #0
	mov	r0, r3
	sub	sp, fp, #4
	@ sp needed
	pop	{fp, lr}
	bx	lr
.L18:
	.align	2
.L17:
	.word	USART1
	.size	main, .-main
	.ident	"GCC: (15:9-2019-q4-0ubuntu1) 9.2.1 20191025 (release) [ARM/arm-9-branch revision 277599]"
