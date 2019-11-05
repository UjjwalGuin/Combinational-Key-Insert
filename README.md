# Design for Security

## Overview
The DFS program parses the netlist file of a synthisized design and inserts key gates connected to randomly selected wires. The program then generates a modified netlist file with the newly inserted gates. This is used in the Design-for-Security architecture that proposes to insert a secure cell in addition to the key gates to ensure the key is not leaked during manufacturing tests.

For more information about the research and methodology see [Robust Design-for-Security Architecture for Enabling Trust in IC Manufacturing and Test](https://ieeexplore.ieee.org/document/8290974)

## Background
Due to the prohibitive costs of semiconductor manufacturing, most system-on-chip design companies outsource their production to offshore foundries. As most of these devices are manufactured in environments of limited trust that often lack appropriate oversight, a number of different threats have emerged. These include unauthorized overproduction of the integrated circuits (ICs), sale of out-of-specification/rejected ICs discarded by manufacturing tests, piracy of intellectual property, and reverse engineering of the designs. Over the years, researchers have proposed different metering and obfuscation techniques to enable trust in outsourced IC manufacturing, where the design is obfuscated by modifying the underlying functionality and only activated by using a secure obfuscation key. However, Boolean satisfiability-based algorithms have been shown to efficiently break key-based obfuscation methods, and thus circumvent the primary objectives of metering and obfuscation. In this paper, we present a novel secure cell design for implementing the design-for-security infrastructure to prevent leaking the key to an adversary under any circumstances. Importantly, our design does not limit the testability of the chip during the normal manufacturing flow in any way, including postsilicon validation and debug. Our proposed design is resistant to various known attacks at the cost of a very little (< 1%) area overhead.

## Usage
```
perl conb_key_ins.pl [FLAG] [VALUE]
```

| Use                    | Name          | Flag  |
| ---------------------- |---------------| ------|
| Usage Info             | `--help`      | -     |
| Debug                  | `--debug`     | -     |
| Filename               | `--file`      | `-f`  |
| Max Wires              | `--maxwire`   | `-w`  |
| Max Gates              | `--maxgate`   | `-g`  |
| Reset Signal           | `--reset`     | `-r`  |
| Number of Scan Chains  | `--cn`        | `-s`  |
| Previous Chain Out     | `--co`        | `-o`  |
| Number of Gate Inserts | `--inserts`   | `-i`  |
| Number of High Values  | `--high`      | `-h`  |

## Methodology

#### Setup
First, the key is added to the key file {file}_key.txt.  Next, the program reads in inputs, outputs, and wires from the original file and copies them over to a working file.  The newly created wires are inserted into the working file at this point.  Note that for the program to function properly you must add the //add;, //gate;, and //new; lines to the input file.  This tells the program where to insert the newly created components. The initial comments must also be removed in order for the script to
parse the netlist properly. 

Now the inputs, outputs, and wires are separated into the ip, op, and wi files respectively.  Lines that have been "combined" are then unrolled by pre_unfold.py so that each component is on a separate line.

#### DFF Parsing
Parses the netlist to initialize DFFs loads additional wires into the sout array if necessary.

#### Wire Picks
Wires to be used for the inserted gates are randomly chosen by the program unless they are used for a Multiplexer, Buffer, or Inverter.

#### Gate Insert
This section builds generated the new code for the xor gates that are being inserted.  

