# **SHA-256 Implementation and Analysis in Kernel Space, User Space, and System Calls**
Operating Systems Term Project

Authors:
- Ameera Ali
- Syeda Zehra Imam
  
## **Project Overview**
This project involves implementing and analyzing the SHA-256 cryptographic hash algorithm in three environments:

1. Kernel Space
2. User Space
3. System Calls
Our analysis focuses on the development, testing, performance evaluation, and security implications of the algorithm in each environment.

## **Technical Details**
- Programming Languages: C, RISC-V Assembly
- Platform: xv6 operating system with RISC-V architecture
- Tools and Frameworks:
  - xv6: Customizing and testing in the xv6 kernel.
  - QEMU: Emulating RISC-V for testing and debugging.
  - Git: Version control and collaboration.
  
## **Features**
1. Kernel Space Implementation:
  - Direct integration of SHA-256 into the xv6 kernel.
  - Analysis of kernel-specific performance overheads.

2. User Space Implementation:
  - Implementation as a standalone program in user space.
  - Testing with various input sizes and data types.

3.System Call Integration:
  - Addition of a custom system call for SHA-256.
  - Evaluation of the syscall interface's impact on performance and usability.
  
## **Acknowledgements**
We extend our gratitude to our Operating Systems instructor Dr.Waseem Arain for his guidance and support throughout the project.
