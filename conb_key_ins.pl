# This file is part of https://github.com/UjjwalGuin/Design-For-Security

# Design-For-Security is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as 
# published by the Free Software Foundation, either version 3 of the 
# License, or (at your option) any later version.

# Design-For-Security is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS For A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with design-for-security.  If not, see <https://www.gnu.org/licenses/>.

use strict;
use warnings;
use diagnostics;

use feature 'say';
use feature "switch";
use Getopt::Long;
use List::MoreUtils qw(any) ;
use Data::Dumper qw(Dumper);
use List::MoreUtils qw/first_index/;

my $file = "c432";
my $maxwire = 60000;
my $maxgate = 60000;
my $reset = "n3643";	#reset signal;
my $cn = 9;		#number of scan chain;
my $co;			#previous chain out; 
my $n = 10;		# NO.of gate insert
my $high = 4;		#the number of high values (k=1);

my @search = ("AND", "NAND", "OR", "NOR", "XOR", "XNOR", "OA", "OAI", "AO", "AOI");
my @found = ("NAND", "AND", "NOR", "OR", "XNOR", "XOR", "OAI", "OA", "AOI", "AO");

my @backinv;

my @exclude; 		#exclude wire;
my @selected = ();	#selected wire

my @PI = (); 		#primer input;
my @PO = (); 		#primer output;
my @wire = (); 		#wire number
my @PP = (); 		#total nodes;
my @dff_Q = ();		#DFF Q;
my @dff_QN = ();	#DFF QN;
my @dff_SI = ();	#Scan In;
my @dff_D = ();		#DFF D;
my @RS = ();

my @sout ;		#last wire of each scan chain out;
my @to ;		#output temp array;

my $help = '';

################################################################################
# Command Line Arguments Parsing
################################################################################
GetOptions("help"			=> \$help,
		   "file|f=s"		=> \$file,
		   "maxwire|w=i" 	=> \$maxwire, 
		   "maxgate|g=i" 	=> \$maxgate,
		   "reset|r=s" 		=> \$reset,
		   "cn|s=i" 		=> \$cn,
		   "co|o=i" 		=> \$co,
		   "inserts|n=i"	=> \$n,
		   "high|h=i" 		=> \$high)
or die("Error in command line arguments\n");

if ($help) {
	print "usage: conb_key_ins.pl [FLAG] [OPTION]\n";
	print "[-w <max wires>] [-g <max gates>] [-r <reset>]\n";
	print "[-s <num scan chains] [-c <prev chain out>]\n";
	print "[-n <num gate insert>] [-h <num high values>]\n";
	exit 1;
}

# Appends the key value to {$file}_key.txt
key_append($file, $n, $high);

# copies the contents {file}_test.v into {file}_in.v
# and inserts the newly created wires.
my @w = build_working_file($file, $maxwire, $n);

################################################################################
# Builds the files for the wires, outputs, and inputs
################################################################################
open(my $in_fh,"<","./${file}/${file}_in.v") or die"cannot open the file:$!\n";
open(my $ip_fh,">","./${file}/ip") or die"cannot open the file:$!\n";
open(my $op_fh,">","./${file}/op") or die"cannot open the file:$!\n";
open(my $wi_fh,">","./${file}/wi") or die"cannot open the file:$!\n";

while (my $line=<$in_fh>){	
	
	my $ex1 = index($line, "INV");
	my $ex2 = index($line, "MUX");
	my $ex3 = index($line, "NBUFF");

	if($ex1 ne -1 or $ex2 ne -1 or $ex3 ne -1){
		my $output = substr ($line, index($line,".Y(")+3, index($line,") );")-index($line,".Y(")-3, "");
		push @exclude, $output;
	}	

	if (index($line, "input") ne -1) {
		$line =~ s/input//;
		$line =~ s/^\s+|\s+$//g;
		chomp($line);

		my @array = split(/, |;|,/,$line);
		foreach (@array) {
    		 print $ip_fh $_,"\n";
		}
	}

	if (index($line, "output") ne -1) {
		$line =~ s/output//;
		$line =~ s/^\s+|\s+$//g;
		chomp($line);

		my @array = split(/, |;|,/,$line);
		foreach (@array) {
    		 print $op_fh $_,"\n";
		}
	}

	if (index($line, "wire") ne -1) {
		$line =~ s/wire//;
		$line =~ s/^\s+|\s+$//g;
		chomp($line);

		my @array = split(/, |;|,/,$line);
		foreach (@array) {
    		 print $wi_fh $_,"\n";
		}
	}
}
close $in_fh;
close $ip_fh;
close $op_fh;
close $wi_fh;

################################################################################
# Unroll wires that have been combined
################################################################################
system `python pre_unfold.py ./${file}/ip ./${file}/ip_un`;
system `python pre_unfold.py ./${file}/op ./${file}/op_un`;
system `python pre_unfold.py ./${file}/wi ./${file}/wi_un`;

open(my $ip_un_fh,"<","./${file}/ip_un") or die"cannot open the file:$!\n";
while (my $line=<$ip_un_fh>){
	chomp($line);
	push @PI, $line;
	push @PP, $line;
}
close $$ip_un_fh;

open(my $wi_un_fh,"<","./${file}/wi_un") or die"cannot open the file:$!\n";
while (my $line=<$wi_un_fh>){
	chomp($line);
	push @wire, $line;
	push @PP, $line;
}
close $wi_un_fh;

open(my $op_un_fh,"<","./${file}/op_un") or die"cannot open the file:$!\n";
while (my $line=<$op_un_fh>){
	chomp($line);
	push @PO, $line;
	push @PP, $line;
}
close $op_un_fh;

my $i;
for($i=0; $i<$cn; $i++){
	$sout[$i] = "test_so$i";
}

################################################################################
# Parsing for initializing DFFs into thier appropriate arrays and loading 
# additional wires into the sout array if necessary.
################################################################################
open($in_fh,"<","./${file}/${file}_in.v") or die"cannot open the file:$!\n";

while (my $line=<$in_fh>){

	my $t = ();
	my $r = $line;
	my $str_val;
	my $shift_val;

	if (index($line,"input") != -1) {$str_val="input "; $shift_val=6}
	if (index($line,"output") != -1) {$str_val="output "; $shift_val=7}
	if (index($line,"wire") != -1) {$str_val="wire   "; $shift_val=7}
	
	if (index($line,"input") != -1 or
		index($line,"output") != -1 or
		index($line,"wire") != -1) {

		substr($r,0,index($r,$str_val)+$shift_val,"");
		if (index($line,":")!=-1){
			my $r1 = $line;
			my $r2 = $line;
			substr($r1,0,index($r1,"]")+2,"");#get line name and number;
			$r1 = substr($r1,0,index($r1,";"),"");
			substr($r2,0,index($r2,"[")+1,"");#get line name and number;
			$r2 = substr($r2,0,index($r2,":"),"");
			
			if (index($line,"wire") != -1) {
				print "r2 $r2 TEST\n\n";
			}
            
			$t = $r1;
			for($i = 0; $i<=$r2; $i++) {
				 $t .= "[";
				 $t .= "$i";
				 $t .= "]";
				 $t = $r1;
			}
		}
		
		elsif(index($line,",")!=-1){
			my $lc = length $line;
			while($lc > 2){
		
				if(index($r,"," ) != -1){
					substr($r,0,index($r,"  ")+1,"");
					$t = substr($r,0,index($r,","),"");
					substr($r,0,index($r,",")+2,"");
				}
				
				elsif(index($r,"," ) == -1 && index($r,";") != -1) {
					if(index($r," ") == 0){
						substr($r,0,index($r," ")+1,"");	
					}					
					$t = substr($r,0,index($r,";"),"");
				}
				$lc = length $r;
			}
		}
			
		elsif(index($line,",") == -1 && index($line,";") != -1) {
			if(index($r," ") == 0) {
				substr($r,0,index($r," ")+1,"");	
			}
			$t = substr($r,0,index($r,";"),"");
		}
	}

	if (index($line,"assign test_") != -1) {
		substr($r,0,index($r,"assign test_so")+14,"");
		$t = substr($r,0,index($r," = ")+3,"");
		print "t1 is\t";	
		print $t."\n";
		substr($t,index($t," = "),3,"");
		substr($r,index($r,";"),2,"");
		print "t2 is\t";	
		print $t."\n";
		print "s is\n";	
		print $r."\n";
		$sout[$t] = $r; 
	}

	my $tem= (); 	#tem input line;
	my $read1; 	#line temp; 
	my $read2; 	#line temp; 
	my $read3; 	#line temp; 
	my $str_ins;

	if (index($line,"DFFARX") != -1) {
		$tem = $line;
		substr($tem,0,index($tem,"D(")+2,"");		
		substr($tem,index($tem,")"),index($tem,";"),"");		
		$read1 = $tem;		
		push @dff_D, $read1;
	}

	if (index($line,"DFFARX") != -1 && index($line,"Q(") != -1){
		$tem = $line;		
		substr($tem,0,index($tem,"Q(")+2,"");		
		substr($tem,index($tem,")"),index($tem,";"),"");
		$read2 = $tem;			
		push @dff_Q, $read2;
	}

	if (index($line,"DFFARX") != -1 && index($line,"QN") != -1){
		$tem = $line;		
		substr($tem,0,index($tem,"QN(")+3,"");		
		substr($tem,index($tem,")"),index($tem,";"),"");		
		$read3 = $tem;
		push @dff_QN, $read3;
	}

	if (index($line,"DFFARX") != -1 && index($line,"SI") != -1){
		$tem = $line;		
		substr($tem,0,index($tem,"SI(")+3,"");		
		substr($tem,index($tem,")"),index($tem,";"),"");		
		$read3 = $tem;		
		push @dff_SI, $read3;
	}

	if (index($line,"DFFARX") != -1 && index($line,"RSTB(") != -1){
		$tem = $line;		
		substr($tem,0,index($tem,"RSTB(")+5,"");		
		substr($tem,index($tem,")"),index($tem,";"),"");		
		$read2 = $tem;		
		push @RS, $read2;
	}
}
print "\n\n";
print "sout @sout";
print "\n\n";

################################################################################
# Select wires to use for newly inserted gates
################################################################################
$i = 1;
while($i <= $n){
	
	my $s = $wire[rand@wire];
	
	if ((any {$s eq $_ } @dff_Q) !=1 && 
		(any {$s eq $_ } @dff_QN) !=1 && 
		(any {$s eq $_ } @selected) !=1 && 
		(any {$s eq $_ } @dff_SI) !=1 && 
		(any {$s eq $_ } @dff_D) !=1 && 
		(any {$s eq $_ } @RS) !=1) {

		if ($i <= $high) {
		
			my $res = any {$s eq $_ } @exclude;
			if($res ne 1 ){
				#print "No repick";
				push @selected, $s;
				$i = $i +1;
			
			} else {
				print "Need repick\n";
				print "Ro $s\n";
			}
		
		} else {
			push @selected, $s;
			$i = $i +1;
		}
	}
}

################################################################################
# Inserts newly created gates into the code
################################################################################
open(FH,"<","./${file}/${file}_in.v") or die"cannot open the file:$!\n";
open(AK,">","./${file}/${file}_test_out.v") or die"cannot open the file:$!\n";
while (my $line=<FH>){
	my $tline = $line;
	
	if(index($line,"//gate") ne -1) { #replace the selected wire in output with new wire;
		
		for (my $i = 0; $i <= $#selected; $i++) {
			if($i < $high) {
				
				my $bt = $selected[$i] . ")";	

				$a= index($line,$bt);

				if (index($line,"HADDX") != -1){		
					my $y1= index($line,".C1(");
					my $y2= index($line,".SO(");
					if (($a-$y1 <= 4 && $a-$y1 > 0) or ($a-$y2 <= 4 && $a-$y2 > 0)) {
						substr($line,index($line,$bt),length ($bt)-1,$w[$i]); 
					}
				}
				
				elsif(index($line,"FADDX") != -1){
					my $y1= index($line,".CO(");
					my $y2= index($line,".S(");
					if (($a-$y1 <= 4 && $a-$y1 > 0) or ($a-$y2 <= 4 && $a-$y2 > 0)) {
						substr($line,index($line,$bt),length ($bt)-1,$w[$i]); 
					}
				}

				elsif(index($line,"SDFFARX") != -1){
					my $y1= index($line,".Q(");
					my $y2= index($line,".QN(");
					if (($a-$y1 <= 4 && $a-$y1 > 0) or ($a-$y2 <= 4 && $a-$y2 > 0)) {
						substr($line,index($line,$bt),length ($bt)-1,$w[$i]); 
					}
				}
				
				elsif(index($line,"MUX21X") != -1){
					my $y1= index($line,".Y(");
					if (($a-$y1 <= 4 && $a-$y1 > 0)){
						substr($line,index($line,$bt),length ($bt)-1,$w[$i]); 
					}
					print "There is a MUX need to modify\n";
				}

				else {
					if ($a != -1) {
						my $y1= index($line,".Y(");
						if (($a-$y1 <= 4 && $a-$y1 > 0)){
							$_= $line;
							
							if (m/([A-Z]+)\d+/) {
								
								my $lo = first_index { $_ eq "$1" } @search;  
								if ( $lo ne -1 ) {
									
									$backinv[$i] = substr ($tline, index($tline,"RVT")+4, 
										index($tline," ( .")- index($tline,"RVT")-4, "");
									substr ($tline, index($tline,"RVT")+4, index($tline,
										" ( .")- index($tline,"RVT")-4, "$backinv[$i]");
									my $t3;
									$t3 = substr ($tline, index($tline, ".Y(")+3, 
										index($tline,") );")-index($tline, ".Y(")-3, $w[$i]);
									$t3 = substr ($tline, index($tline, ".Y(")+3, 
										index($tline,") );")-index($tline, ".Y(")-3, $w[$i]);
									
									substr ($tline, index($tline, "$search[$lo]"), 
										length($search[$lo]), "$found[$lo]");
									
									$line = $tline;
								}
							}
							
						} else {
							my $y1= index($line,".Y(");
							if (($a-$y1 <= 4 && $a-$y1 > 0)){
								#match gate and substitute;
								substr($line,index($line,$bt),length ($bt)-1,$w[$i]); #

							}
						}
					}
				}
			}
		}

		my $num = 0;
		for($i = 0; $i <= $#sout; $i++){
			if (index($line, $sout[$i]) != -1){
				print $i;
				print "$line";
				
				print "line1 $line";		
				substr($line, index($line, $sout[$i]), length $sout[$i], $w[$num + $n]);	
				
				$to[$i] = $w[$num+$n];
				$num = $num + 1;
			}
		}
	}
	
	if(index($line,"//new") != -1){ #add new xor, MUX, DFF;
		my $gate_string = "";
		my $mk = 0;
		my $xor= "  XOR2X1_RVT U";		
		my $A1 = " ( .A1("; # old wire;
		my $A2 = "), .A2("; # new wire;
		my $Y = "), .Y(";
		my $end = ") );"; #line end;
		my $nw1 = $maxwire;
		my $ow =  "";
		my $nw2 = $maxwire+$n;
		my $ng = $maxgate;
		my $set_hi;

		my $dff = "  SDFFARX1_RVT ";		
		my $D = " ( .D("; # old wire;
		my $CK = "), .CLK(CK"; # new wire;
		my $RSTB = "), .RSTB(";
		my $Q = "), .Q(";

		my $MUX = "  MUX41X1_RVT U";		
		my $A3 = "), .A3("; #  wire;
		my $A4 = "), .A4("; #  wire;
		my $S0 = "), .S0("; #  wire;
		my $S1 = "), .S1("; #  wire;

		my $num = 0;
		my $ct = 0; # chain counter;
		
		while($num <= $n-1){		
			if($num < $high){
				$set_hi = "1'b1";
			} else {
				$set_hi = "1'b0";					
			}
			# need the array of last wire in chain
			$ng = $ng + 1;		
			$ow = $selected[$num];
			$nw1 = $nw1 + 1; 
			$gate_string = "";
			$gate_string = $xor. $ng . $A1 . $w[$num] . $A2 . $set_hi .
				$Y . $ow . $end . "\n";
			
			print AK $gate_string;
	
			if($ct == $cn-1) {
				$ct = 0;
			}

			else {
				$ct = $ct + 1;
			}
			$mk = $mk + 1 ;
			$num = $num +1;
		}
	}
	print AK $line;
}
close (FH);
close (AK);

################################################################################
# copies the contents {file}_test.v into {file}_in.v
# and inserts the newly created wires.
################################################################################
sub build_working_file {
	my ($file, $maxwire, $n) = @_;
	my @w;
	my $nx = "n";
	# file modify, {file}_in.v
	open(my $fh_read,"<","./${file}/synt/${file}_test.v") 
		or die "cannot open the file:$!\n";
	open(my $fh_write,">","./${file}/${file}_in.v")
		or die "cannot open the file:$!\n";

	while (my $line = <$fh_read>) {
		if (index($line, "input") ne -1 or
			index($line, "output") ne -1 or
			index($line, "wire") ne -1) {
			
			if (index($line, ";") eq - 1 ) {
				my $line_comb = "";
				do {
					chomp($line);
					$line =~ s/^\s+//;
					$line_comb = $line_comb . " " . $line;
				} while (index($line=<$fh_read>, ";") eq -1);
				chomp($line);
				$line =~ s/^\s+//;
				$line_comb = $line_comb . " " . $line;
				print $fh_write "$line_comb\n";
			} else {
				chomp($line);
				$line =~ s/^\s+//;
				print $fh_write "$line\n";
			}	

		} elsif (index($line, "//add") ne -1) {
			my $mw = $maxwire;
			my $wire_name = '';
			my $num = 0;
			while($num <= $n-1){
				$wire_name = $nx . ($mw + $num + 1);
				$num += 1;
				
				push @w , $wire_name;
				if ($num < $n) {
					print $fh_write $wire_name . ", ";
				}
				else {
					print $fh_write $wire_name . ";\n";
				}
			}

		} elsif (index($line, "//gate") ne -1) {
			while (index($line=<$fh_read>, "//new") eq -1) {
				if (index($line, ";") eq - 1 ) {
					my $line_comb = "";
					do {
						chomp($line);
						$line =~ s/^\s+//;
						$line_comb = $line_comb . " " . $line;
					} while (index($line=<$fh_read>, ";") eq -1);
					chomp($line);
					$line =~ s/^\s+//;
					$line_comb = $line_comb . " " . $line;
					print $fh_write "$line_comb\n";
				} else {
					chomp($line);
					$line =~ s/^\s+//;
					print $fh_write "$line\n";
				}
			}
			print $fh_write "//new;\n";
		
		} else {
			print $fh_write "$line";
		}
	}
	close $fh_read;
	close $fh_write;

	return @w
}

################################################################################
# Appends the key value to {$file}_key.txt
################################################################################
sub key_append {
	my ($file, $num_inserts, $high_vals) = @_;
	for(my $i=1; $i <= $num_inserts; $i++)
	{
		open(AK,">>","./${file}/${file}_key.txt") or die"cannot open the file:$!\n";
		if($i <= $high_vals){
			print AK "1\t";
		}else{
			print AK "0\t";
		}
		close AK;
	}
}
