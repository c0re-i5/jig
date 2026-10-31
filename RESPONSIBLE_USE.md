# Responsible use

rehost is a firmware-agnostic rehosting toolkit for **authorized security research**. It is in the same category of tooling as QEMU, Unicorn, Renode, and Ghidra: engines, memory maps, peripheral models, snapshots, and harnesses.

This is not legal advice.

## What this project ships

The repository contains the framework, its tests, and small synthetic Cortex-M programs assembled from source in this tree. Those programs exist so CI can exercise UART, GPIO, and SysTick stubs.

The project does **not** distribute, mirror, download, or commit third-party firmware, ROMs, BIOS images, or proprietary dumps. A machine config names addresses and plugins. The image path is an argument you pass at runtime from a file you already have.

## What you bring

Use rehost on a target you are allowed to analyze. That means you hold the image under your own authorization: you own the device, you administer it, your employer or client engaged you to test it, a bug-bounty program covers it, or you are working from hardware in your lab under the same kind of permission. Keep the image on your machine. Do not add it to this repository, a fork, or a bug report.

If you build a larger fixture yourself, prefer source you can rebuild: a Zephyr sample, a FreeRTOS demo, or your own bare-metal program. The framework will load the raw image you point it at. It will not fetch one for you.

## Disclosure

When analysis of an authorized target turns up a vulnerability, report it through coordinated vulnerability disclosure. Start with the vendor's product security team (PSIRT) when they have one. National coordination points include:

- [CISA coordinated vulnerability disclosure](https://www.cisa.gov/coordinated-vulnerability-disclosure-process)
- [Canadian Centre for Cyber Security](https://www.cyber.gc.ca/en)

Give the vendor a chance to fix the issue before public detail, and share enough for them to reproduce it without publishing exploits or someone else's firmware.

## Law that researchers often look up

These citations are orientation, not a safe harbor and not advice on your facts.

- Canada: [Copyright Act s. 41.15](https://laws-lois.justice.gc.ca/eng/acts/C-42/section-41.15.html) allows circumvention of a technological protection measure for security assessment of a computer, system, or network with the consent of the owner or administrator, and not where the assessment would commit another infringement or an offence.
- United States: the DMCA security-research exemption in [37 CFR 201.40](https://www.ecfr.gov/current/title-37/chapter-II/subchapter-A/part-201/section-201.40) is a narrow, good-faith class with its own conditions. It does not authorize access that other law, including the CFAA, forbids.

Other countries have their own rules. Authorization to analyze a device you were given is the starting point; the framework does not create that authorization.
