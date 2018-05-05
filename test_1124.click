CONTROL :: ControlSocket(tcp,22222)
out :: RED(768,1024,0.02)->Queue(1024) -> ToDevice(ens34)
FromDevice(ens34)-> cl :: Classifier(12/0806 20/0001,12/0806 20/0002,12/0800)
-> arpr :: ARPResponder(192.168.3.128, 00:0c:29:44:f4:4c)
->out;
cl[1] -> [1]arpq :: ARPQuerier(192.168.3.128,00:0c:29:44:f4:4c)
->out;
->cl[2]->Strip(14)
-> CheckIPHeader(CHECKSUM false)
->DropBroadcasts
->CheckLength(65535)
-> IPPrint("recv IP detail")
ic :: IPClassifier( dst 192.168.3.255 and icmp,dst 192.168.3.128 and src 192.168.3.128,src 10.1.1.2,src 10.1.1.3,-)ic[0]->discard
ic[1]->discard
ic[2]->discard
ic[3]->discard
ic[4]->->rw :: IPRewriter(pattern - - 192.168.3.129 -0 0)
-> dt :: DecIPTTL
-> fr :: IPFragmenter(300)
-> IPPrint("send IP detail")-> arpq;

