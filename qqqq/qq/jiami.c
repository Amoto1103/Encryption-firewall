int jiami(char *msg)
{
	//hash
	int a=0;
	a=RSHash(msg,strlen(msg));
	char abst[100];
	sprintf(abst,"%d",a);
	//printf("result:%s\n",abst);

	//signature
	PCHAR na="qMvq04wETHyfiYOw1yVLy9fpxaUJpzL3SXO10pL1yUB81lX8tQqvGTe1Bp4xLL9RRmpq9P9nGAkExbrjp66WoyanIxR4ml9k3Hd6CVse3BWTIJbrdPRV8cG7zVbAzFyFxqsUinDBzJwwqv7ENRLXwJ7QchfWoBjn2d9aPVFpcRzknIJLBXAAEGuZxCaV96Mpv94icEg1v50BWQjJhpZnPwYB5pstXOLG5brO5UhCXy6xUO6pUMoIVFGW6LPBW9PNtiomdOKl35sjLuEHwczvyKYNgPLH95Lg0EEieRyVgzX3cL0nPht9SMZzKg3wVgkColoaiWyjzVkLHSTPU6nDUFAD";
    PCHAR da="BqBU51d5nREpYxDlwmpIDyrPBZbhTIzpwyu1fwhw7Lzbiw8JNdCI48dqVyDFxuidWPodqrIDV3aUwvC59lO2xWsRgcCoZoYFMuiMJN3oZA8Jwf7WYNsKZwITSGDJfQpz0B0xbqhwGLlbDYd0rI8XazdeHoOIsuH4Di0ffoYNR9VxktifvWd1IkI0NM9XVSbPf7JGKLQS3bgDMTQi6Lh7XwNdC6siZHcsIga2tmEKbtKkerZDNSNgsiZfcufkSoeJmEZpWkAYhh7e8tYjUfI9p5D4jdXoRNBPv2X7NPrh0BHrcUEZWOurVdvAZfDUw8aK7OJ4nEdRLvsbDFrlBlMvLMPp";
	PCHAR eb="H33";
    PCHAR nb="qMvq04wETHzGVQwqkh4BCUMSb0ch1R33thkUw8f5qFDARQCS0DvfpKQ7MRKWA4BjY9ZAyJY4jijhoxbXud5GM6LAtEETM7EkJpQdgNqYP9sO0sEXrlaar4gweC3syNvPuiLQCTaKU5sfFA1PI6iNUdNgkCsBk6Jl2gw5lEO5GxXp5IJlG3tpx9YAeITv3rYl0BN7sIn2g4A3O9eBjO1O84v2ixmqvSMVUqTIcx7vwbrzCBHeWTTq0ElajkB0ce9EoIxXplcddlYACz98ixBqMYWnQ0tVoGNg4PvBpBXBaVwhiLzREWbVsbDtncHJUKTJDVKsEAAEm5yumhMxz6tReUuz";
	PCHAR sign1 = (PCHAR) malloc(strlen(msg) + 400);
	cipher(abst, strlen(abst), na, da, &sign1);
	//printf("sign:%s\n",sign1);
	//printf("length:%d\n",strlen(sign1));
	PCHAR merge = (PCHAR) malloc(strlen(msg) + 400);
	sprintf(merge, "%s%s", sign1, msg);
	//printf("length:%d\n",strlen(merge));
	//printf("merge:%s\n",merge);

	//AES
	const uint8_t key2[]="1234567890123456";
	int len = strlen(merge);
	//printf("length:%d\n",len);
	while (len % BLOCKSIZE)
	{
		*(merge + len) = '\0';
		len++;
	}
	//printf("length:%d\n",len);
	const uint8_t *data = (uint8_t*)merge;
	uint8_t ct2[1000] = {0};
	aesEncrypt(key2, 16, data, ct2, len);
	//printHex(ct2, len, "after encryption:");
	PCHAR miwen = (PCHAR) malloc(1000);
	memset(miwen, 0, 1000);
	for (int i = 0; i < len; ++i) 
	{
		char p[10];
		//printf("%d\n",ct2[i]);
		sprintf(p,"%.2X",ct2[i]);
		strcat(miwen,p);
	}
	//printf("miwen:%s\n",miwen);

	//envelope
	PCHAR env = (PCHAR) malloc(400);
	memset(env, 0, 400);
	char pk[100]="1234567890123456";
	cipher(pk, strlen(pk), nb, eb, &env);
	//printf("env=:%s\n",env);

	//result
    PCHAR result = (PCHAR) malloc(1500);
	memset(result, 0, 1500);
    sprintf(result,"%s%s",env,miwen);
	//printf("length:%d\n",strlen(result));
    //printf("result=:%s\n",result);

	while (*msg++ = *result++);	

    return 0;
}

// int main()
// {
// 	char msg[]="abcdefghijklmnopqrstuvwxyz";
// 	jiami(msg);
// 	printf("%s\n", msg);
// 	return 0;
// }
