#include "analysisPcap.h"


uint32 hash_5_tuple(struct flowTuple *pkt){
	uint32 hash_index = 0;
	//hash_index = pkt->src_ip % PRIME;
	hash_index = (pkt->src_ip + pkt->dst_ip + (uint32) pkt->src_port + (uint32) pkt->dst_port) % PRIME;
	return hash_index;
}

void analysisInitial(tBigFlowTable *bigFlowTable, tBigFlowTable *bigFlowTable_c){
	int i = 0;
	for(i =0; i < NUM_BIG_FLOW_ENTRY; i++){
		bigFlowTable[i].count_pkt = 0;
		bigFlowTable[i].count_size = 0;
		bigFlowTable[i].eNext = NULL;
		bigFlowTable_c[i].count_pkt = 0;
		bigFlowTable_c[i].count_size = 0;
		bigFlowTable_c[i].eNext = NULL;
	}
}


int analysisPacket(FILE *fp_pkt, FILE * fp_pkt_tag,tBigFlowTable *bigFlowTable, tBigFlowTable *bigFlowTable_c){
	if((fp_pkt_tag = fopen("result_pkt_2.txt","w"))==NULL){
		printf("open result_pkt_2.txt error\n");
		exit(0);
	}

	if((fp_pkt = fopen("result_pkt.txt","r"))==NULL){
		printf("read result_pkt.txt error\n");
		exit(0);
	}

	uint32 hash_index = 0;
	uint32 conflict_index = 0;	// used to allocate bigFlowTable_c entry;
	tBigFlowTable *pBFT, *preBFT;
	int i;
	int num_flow = 0;
	int num_pkt = 0;
	//for(i = 0; i< num_pkt; i++){
	struct pktTuple pkt;
	while(fscanf(fp_pkt, "%x\t%x\t%hd\t%hd\t%hhu\t%u\t%d\t%d\n", &pkt.ft.src_ip, &pkt.ft.dst_ip, &pkt.ft.src_port, &pkt.ft.dst_port, &pkt.ft.proto,
		&pkt.pktLen,&pkt.tv.tv_sec, &pkt.tv.tv_usec)!= EOF){
		if(pkt.ft.proto != 0x6)
			continue;
		/*fprintf(fp, "%d\t%x\t%x\t%hd\t%hd\n", i, pkt[i].src_ip, pkt[i].dst_ip,
			pkt[i].src_port,pkt[i].dst_port);*/
		
		// calculate hash value;
		hash_index = hash_5_tuple(&pkt.ft);
		pBFT = bigFlowTable[hash_index].eNext;
		preBFT = &bigFlowTable[hash_index];



		if(bigFlowTable[hash_index].count_pkt == 0){
			cpyFlowTuple(&(bigFlowTable[hash_index].ft), &pkt.ft);
			pkt.ft.tag = 1;
			bigFlowTable[hash_index].eNext = NULL;		
			num_flow++;
			bigFlowTable[hash_index].count_pkt = 1;
			bigFlowTable[hash_index].count_size = pkt.pktLen;
		}
		else if(cmpFlowTuple(&bigFlowTable[hash_index].ft, &pkt.ft) == 0){
			pkt.ft.tag = 0;
			bigFlowTable[hash_index].count_pkt ++;
			bigFlowTable[hash_index].count_size += pkt.pktLen;
		}
		else{
			while(pBFT != NULL){
				if(cmpFlowTuple(&(pBFT->ft), &pkt.ft) == 0){
					pBFT->count_pkt ++;
					pBFT->count_size += pkt.pktLen;
					pkt.ft.tag = 0;
					break;
				}
				preBFT = pBFT;
				pBFT = pBFT->eNext;
			}
			if(pBFT == NULL){
				cpyFlowTuple(&(bigFlowTable_c[conflict_index].ft), &pkt.ft);
				pkt.ft.tag = 1;
				num_flow++;

				bigFlowTable_c[conflict_index].count_pkt = 1;
				bigFlowTable_c[conflict_index].count_size += pkt.pktLen;
				preBFT->eNext = &bigFlowTable_c[conflict_index];
				conflict_index +=1;
			}
		}
		fprintf(fp_pkt_tag, "%x\t%x\t%hd\t%hd\t%d\t%d\t%u\t%d\t%d\n", pkt.ft.src_ip, pkt.ft.dst_ip,
			pkt.ft.src_port,pkt.ft.dst_port, pkt.ft.proto, pkt.ft.tag, pkt.pktLen, pkt.tv.tv_sec, pkt.tv.tv_usec);

		num_pkt++;
		if((num_pkt > MAX_NUM_PACKET) || (num_flow > MAX_NUM_FLOW))
			break;
	}
	fclose(fp_pkt);
	fclose(fp_pkt_tag);
	printf("num_pkt:%d\n", num_pkt);
	return num_flow;
}

int calculateRelatedError(tFlowTable *flowTable, int num_flow, tBigFlowTable *bigFlowTable, int *num_error_flow){
	int i = 0;
	int hash_index;
	int num_error = 0;
	tBigFlowTable *pBFT;
	for(i = 0; i< num_flow; i++){
		hash_index = hash_5_tuple(&flowTable[i].ft);
		pBFT = &bigFlowTable[hash_index];
		while((pBFT) && (pBFT->count_pkt != 0)){
			if(cmpFlowTuple(&(pBFT->ft), &(flowTable[i].ft)) == 0){
				num_error += uABS(pBFT->count_pkt, flowTable[i].count);
				if(uABS(pBFT->count_pkt, flowTable[i].count) !=0)
					*num_error_flow += 1;
				break;
			}
			pBFT = pBFT->eNext;
		}
	}
	return num_error;
}

void printBigFlowStatics(FILE *fp, tFlowTable *flowTable, int num_flow, tBigFlowTable *bigFlowTable){
	int i = 0;
	int hash_index;
	tBigFlowTable *pBFT;
	for(i = 0; i< num_flow; i++){
		hash_index = hash_5_tuple(&flowTable[i].ft);
		pBFT = &bigFlowTable[hash_index];
		while((pBFT) && (pBFT->count_pkt != 0)){
			if(cmpFlowTuple(&(pBFT->ft), &(flowTable[i].ft)) == 0){
				fprintf(fp, "%d\t%x\t%x\t%hd\t%hd\t%u\n", i, pBFT->ft.src_ip, pBFT->ft.dst_ip,
					pBFT->ft.src_port, pBFT->ft.dst_port, pBFT->count_pkt);
				break;
			}
			pBFT = pBFT->eNext;
		}
	}
}