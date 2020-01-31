# pairtrack will track the req-res pairs ( for round trip time )
global pairtrack: table[addr] of table[port] of table[count] of table[count] of time;

# pairtrack_bytes will track the req-res pairs ( for bytes exchanged )
global pairtrack_bytes: table[addr] of table[port] of table[count] of table[count] of count;

global rtt_track: vector of double = vector(); 
global goodput_track: vector of double = vector();

event tcp_packet(c:connection, is_orig: bool, flags:string, seq:count, ack:count, len:count, payload: string){
	# in case of cnc-bot analysis, the bot initiates connection but the packet is sent from cnc, so the is_orig should be false
	if(flags == "AP" && is_orig == T){
	#	print is_orig, c$id, flags, seq, ack, len;
	#	print is_orig, c$id$orig_h, c$id$resp_h;

		if(c$id$orig_h !in pairtrack){
			pairtrack[c$id$orig_h] = table();
			pairtrack_bytes[c$id$orig_h] = table();
		}

		if(c$id$orig_p !in pairtrack[c$id$orig_h]){
			pairtrack[c$id$orig_h][c$id$orig_p] = table();
			pairtrack_bytes[c$id$orig_h][c$id$orig_p] = table();
		}

		# now lets calculate the ack number corresponding to this push ack packet
		local next_ack : count = seq + len;
		if( next_ack !in pairtrack[c$id$orig_h][c$id$orig_p]){
			pairtrack[c$id$orig_h][c$id$orig_p][next_ack] = table();
			pairtrack_bytes[c$id$orig_h][c$id$orig_p][next_ack] = table();
		}

		# now we have all the placeholder for the packet
		pairtrack[c$id$orig_h][c$id$orig_p][next_ack][0] = network_time();
		pairtrack_bytes[c$id$orig_h][c$id$orig_p][next_ack][0] = len;

	} else if (is_orig == F) {
		# the response ack is sent from the bot so we track is_orig == T
		# now this should match to one of the above mentioned table
		if(c$id$orig_h in pairtrack && c$id$orig_p in pairtrack[c$id$orig_h] && ack in pairtrack[c$id$orig_h][c$id$orig_p]){
			pairtrack[c$id$orig_h][c$id$orig_p][ack][1] = network_time();
			local rtt:double = interval_to_double( pairtrack[c$id$orig_h][c$id$orig_p][ack][1]-pairtrack[c$id$orig_h][c$id$orig_p][ack][0]);			
			rtt_track[|rtt_track|] = rtt;
			goodput_track[|goodput_track|] = (pairtrack_bytes[c$id$orig_h][c$id$orig_p][ack][0]*8)/rtt;  			
		}
	}
}

event zeek_done(){
	local total_rtt: double = 0.0;
	local total_goodput:double = 0.0; 
        local f_rtt : vector of double = vector();
	local total_frtt: double = 0.0;

	for(i in rtt_track){
		if(rtt_track[i]<0.09){
			f_rtt[|f_rtt|] = rtt_track[i];
		}
	}
	
	for(i in rtt_track){
		total_rtt += rtt_track[i];
	}

	for(i in f_rtt){
		total_frtt += f_rtt[i];
	}

	for(i in goodput_track){
		total_goodput += goodput_track[i];
	}
	print "Total pairs found ", |rtt_track|;
	print "AVG RTT (ms) ", total_rtt*1000/|rtt_track|;
        print "AVG FRTT (ms) ", total_frtt*1000/|f_rtt|;
	print "AVG GOODPUT (bits/s) ", total_goodput/|goodput_track|;
}
