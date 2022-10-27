#!/usr/bin/perl
 
system ("who | cut -d' ' -f1 | sort | uniq");