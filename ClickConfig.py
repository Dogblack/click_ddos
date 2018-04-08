
class ConfigWriter(ControlPort,Strategy,IpDst,IpSrc,IpBrodCast)
    #basic
    Control = 'CONTROL :: ControlSocket(tcp,'+ControlPort+')\n'
    Out_default   = 'out :: Queue(1024) -> ToDevice('+IpDst+')\n'
    Out_red = 'out :: RED(768,1024,0.02)->Queue(1024) -> ToDevice('+IpDst+')\n'
    Is_ip   ='FromDevice('+IpSrc+')-> is_ip :: Classifier(12/0800, -)\n'
    Not_ip  ='is_ip[1]->out\n'
    Set_IPAddr ='SetIPAddress('+IpTo+')'
    Ip_strip = 'is_ip[0]->Strip(14)-> CheckIPHeader(CHECKSUM false) -> CheckLength(65535) -> IPReassembler()'
    red_flag =0

    #strategy
    rst_attack  = 'rst,'
    echo_attack ='dst udp port 7 or 19,'
    smuf_attack ='dst '+IpBrodCast+' and icmp'
    land_attack = 'dst '+IpDst+' and src '+IpDst

    def strategy_init(self):
        Strategy_build=''
        for i in Strategy
            if i == 'rst_attack':
                Strategy_build+= rst_attack
            elif i =='echo_attack':
                Strategy_build += echo_attack
            elif i =='smuf_attack':
                Strategy_build += smuf_attack
            elif i =='land_attack':
                Strategy_build += land_attack
            elif i =='red':
                self.red_flag = 1
            else
                print('ERROR')

        #IpClassfier
        Ip_Classfier = 'ic :: IPClassifier( '+Strategy_build+ '-)'

        port = ''
        for i in rang(len(Strategy))
            port +='ic['+i+']->discard\n'
        port +='ic['+(len(Strategy)+1)+']->'+Set_IPAddr+'->out\n'

        self.Strategy_build =Strategy_build
        self.port = port

    def basic_init(self):
        if red_flag == 0:
           basic =Control + Out_default + Is_ip + Not_ip + Ip_strip
           self.basic =basic
        else:
           basic = Control + Out_red + Is_ip + Not_ip + Ip_strip
           self.basic =basic

    def config_init(self):
        strategy_init()
        basic_init()
        config =self.basic+self.Strategy_build+self.port
        try:
            file = open('config/ddos.click', 'w')
            file.write(config)
        except IOError:
            print('FILE WRITE ERROR')
        else
            print('FILE WRITE SUCCESS')
            file.close()

if __name__ == '__main__':
   ConfigWriter.config_init()





