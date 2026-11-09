import { GROUPS, READ_PARAMS } from '../core.mjs';
export const baseInfo = {code:0,hardware:'RD08',romversion:'1.1.123',countrycode:'CN'};
const radio=(ifname,ssid,device,channel)=>({ifname,ssid,device,status:'1',hidden:'0',encryption:'psk2',password:'not-a-real-network-key',channel:'0',bandwidth:device==='wifi0'?'40':'0',txpwr:'max',channelInfo:{channel,bandList:device==='wifi0'?['20','40']:['20','40','80','160']},available_channels:(device==='wifi0'?[0,1,6,11]:[0,36,48,149]).map(c=>({c,b:device==='wifi0'?['0','20','40']:['0','20','40','80','160']}))});
const clients=[
 {name:'Ноутбук',mac:'02:00:00:00:00:01',type:3,online:1,ip:[{ip:'192.168.31.101'}],statistics:{downspeed:1820000,upspeed:167000,download:7290000000,upload:893000000}},
 {name:'Телефон',mac:'02:00:00:00:00:02',type:3,online:1,ip:[{ip:'192.168.31.102'}],statistics:{downspeed:283000,upspeed:9000,download:1290000000,upload:123000000}},
 {name:'Умная колонка',mac:'02:00:00:00:00:03',type:2,online:1,ip:[{ip:'192.168.31.103'}],statistics:{downspeed:26000,upspeed:5000,download:238000000,upload:3560000}},
];
export const fixture={
 'xqsystem/wps_status':{code:0,status:0},'misystem/speed_test_result':{code:0,status:1},
 'misystem/ota':{code:0,auto:0,plugin:0,time:4},
 'xqsystem/privacy':{code:0,privacy:0},'xqsystem/push_settings':{code:0,auth:1,quiet:0},
 'xqsystem/get_access_force_https':{code:0,on:0},
 'xqsystem/upgrade_status':{code:0,status:0,percent:0},'xqsystem/flash_status':{code:0,status:0},
 'xqsystem/init_info':baseInfo,
 'misystem/status':{code:0,upTime:176400,mem:{usage:.46},cpu:{core:4,load:.07},count:{online:3,online_without_mash:3},wan:{downspeed:2129000,upspeed:181000},hardware:{version:'1.1.123',platform:'RD08'}},
 'misystem/router_name':{code:0,name:'Домашняя сеть',locale:'Гостиная'},
 'xqnetwork/wan_info':{code:0,info:{link:1,status:1,details:{wanType:'dhcp',peerdns:'1',mtu:'1500'},ipv4:[{ip:'198.51.100.24',mask:'255.255.255.0'}],gateWay:'198.51.100.1',dnsAddrs:'1.1.1.1, 8.8.8.8',uptime:176400}},
 'xqnetwork/wifi_detail_all':{code:0,bsd:0,info:[radio('wl1','Дом · 2,4 ГГц','wifi0',6),radio('wl0','Дом · 5 ГГц','wifi1',48)]},
 'misystem/get_ps_map':{code:0,ports:[{port:'1',speed:'2.5G',service:'游戏网口'},{port:'2',speed:'2.5G',service:'LAN'},{port:'3',speed:'2.5G',service:'LAN'},{port:'4',speed:'2.5G',service:'WAN'}]},
 'xqnetwork/get_hostap_mlo':{code:0,mlo_support:1,mlo_enable:0},'xqnetwork/get_twt':{code:0,status:'1'},
 'xqnetwork/get_aimesh_config':{code:0,manual_roaming_setting:'0',roaming_rssi_thr:{'2g':'-65','5g':'-70'}},
 'xqnetwork/get_ch_adj_enable':{code:0,ch_adj_en:0},'xqnetwork/get_miotrelay_switch':{code:0,enabled:0},'xqnetwork/get_wifi_silence':{code:0},
 'xqnetwork/get_wan6_v2':{code:0,wan6_cfg:{ipv6_mode:'off'}},'xqnetwork/get_wan6_info_v2':{code:0,wan6_info:{ipv6_mode:'off',up:false}},'xqnetwork/get_lan6_v2':{code:0,lan6_cfg:{ip6assign:64,mode:'0'}},
 'xqnetwork/lan_info':{code:0,info:{ipv4:[{ip:'192.168.31.1',mask:'255.255.255.0'}]}},
 'xqnetwork/lan_dhcp':{code:0,info:{start:'31',limit:'200',leasetimeNum:'120',leasetime:'120m',ignore:'0',lanIp:[{ip:'192.168.31.1',mask:'255.255.255.0'}]}},
 'xqnetwork/macbind_info':{code:0,list:[{mac:'02:00:00:00:00:01',ip:'192.168.31.101',name:'Ноутбук'}]},
 'misystem/devicelist':{code:0,list:clients},
 'misystem/get_ps_service?service=multiwan':{code:0,multiwan:{enable:0,port_map:[{name:'WAN1',port:'4'},{name:'WAN2',port:'-1'}],policy:{mode:0,bandwidth_wan1:0,bandwidth_wan2:0}}},
 'misystem/get_ps_service?service=iptv':{code:0,iptv:{enable:0,profile:0,vid:-1,priority:-1,ports:''}},
 'misystem/get_ps_service?service=lag':{code:0,lag:{enable:0,mode:2,ports:''}},
 'xqsystem/portforward':{code:0,list:[{name:'Домашний сервер',proto:1,srcport:8443,destip:'192.168.31.110',destport:443}]},
 'xqsystem/upnp':{code:0,status:0,list:[]},'xqsystem/dmz':{code:0,status:0},
 'xqsystem/vpn':{code:0,current:{password:'do-not-expose'},list:[{id:'vpn1',oname:'Домашний VPN',server:'vpn.example.net',username:'example',password:'do-not-expose',proto:'l2tp',iscurrent:0}]},
 'xqsystem/vpn_status':{code:0,status:4,uptime:0},'xqnetwork/ddns':{code:0,list:[{id:'2',domain:'home.example.net',server:'No-IP',enable:1}]},
 'misystem/qos_info':{code:0,status:{on:1,mode:3},band:{upload:100,download:500},list:clients},
 'xqnetwork/get_nfc_info':{code:0,nfc_support:1,nfc_enable:1},'misystem/allled':{code:0,status:'1'},'misystem/led':{code:0,status:0},'misystem/ethled':{code:0,status:'1'},'misystem/sys_time':{code:0,time:{year:2026,month:11,day:8,hour:17,min:0,sec:0,timezone:'<+05>-5',index:'2.75'}},
};
export function fakeRouter() {
  const writes=[];
  return {writes,async login(password){if(password!=='panel-test')throw Error('Bad fixture password');return{stok:'fake-local-session',info:baseInfo,touched:Date.now(),pending:new Map(),busy:false};},async logout(){},async whitelistSession(){return'fixture-authorization';},async api(stok,route,method='GET',params){
    if(method==='GET'&&route==='xqsmarthome/request_smartcontroller'&&JSON.stringify(params)!==JSON.stringify(READ_PARAMS[route]))throw Error('Scene reads require the fixed read payload');
    const parameterReads=['device_security/get_trusted','device_security/get_blocked','device_security/device_status','mi_log/get_logs','config_scanner/get_status','xqnetwork/get_sta_bindinfo','xqnetwork/wan_info','xqnetwork/get_addnode_status'];
    const mutatingGet=['xqnetwork/scan_mesh_node','xqnetwork/channel_scan_start','misystem/qos_guest','xqnetwork/wan_up','xqnetwork/wan_down','xqnetwork/pppoe_start','xqnetwork/pppoe_stop'];
    if((params&&!route.startsWith('misystem/mipctl_get_')&&!Object.hasOwn(READ_PARAMS,route)&&!parameterReads.includes(route))||method!=='GET'||mutatingGet.includes(route)){writes.push({route,method,params});return route==='config_scanner/start'?{code:0,meta:{work_id:'fixture-job'}}:route==='xqnetwork/scan_mesh_node'?structuredClone(fixture[route]):{code:0};}
    if(!(route in fixture))throw Error('Unmapped fixture route: '+route);
    return structuredClone(fixture[route]);
  }};
}
export const testConfig={host:'192.168.31.1',model:'RD08',writeFirmware:'1.1.123',port:18651};
Object.assign(fixture,{
 'xqnetwork/get_roam_rssi_threshold':{code:0,RoamRssiThreshold2G:'-60',RoamRssiThreshold5G:'-60'},
 'xqnetwork/channel_scan_result':{code:0,status:1,'2G':{code:0,cchannel:6,schannel:1,cscore:80,sscore:90,ranking:[]}},
 'xqnetwork/get_mesh_switch':{code:0,enabled:2},
 'xqnetwork/get_multiwan_basic_info':{code:0,info:{enable:0,policy:0,bandwidth_wan1:100,bandwidth_wan2:100}},
 'xqnetwork/get_multiwan_dev_list':{code:0,info:clients},
 'xqnetwork/scan_mesh_node':{code:0,list:[{mac:'02:00:00:00:00:10',ssid:'Новый узел'}]},
 'xqnetwork/get_addnode_status':{code:0,status:2},
 'misystem/mipctl_get_temp_allow':{code:0,allow:false,show:true,nxt_permit:0},
 'device_security/get_global_trusted':{code:0,meta:{trusted:[clients[0].mac]}},
 'device_security/get_trusted':{code:0,meta:{trusted:{[clients[1].mac]:{access_time:1794133800,placeholder:1}}}},
 'device_security/get_blocked':{code:0,meta:{blocked:{[clients[2].mac]:{access_time:1794133800,marked:0}}}},
 'device_security/device_status':{code:0,local_access:{global_enable:0}},
 'url_fw/show_whitelist':{code:0,whitelist:[]},
 'config_scanner/overview':{code:0,meta:{last_score:73},rom_auto_updating:{enable_scan:1},wifi_passwd_secure:{enable_scan:1},UPnP:{enable_scan:1}},
 'config_scanner/get_status':{code:0,meta:{status:2,score:73},wifi_passwd_secure:{status:2,secure:1,enable_scan:1}},
 'mi_log/get_onoff':{code:0,info:{on:1}},'mi_log/overview':{code:0,info:{risk_cnt:2,nic_cnt:5,sys_cnt:1}},
 'mi_log/get_logs':{code:0,total:1,count:1,info:[{date:'2026-11-08',data:[{time:'15:00',ts:1794146400,id:1,type:'risk',msg:'Проверка защиты',mac:clients[1].mac}]}]},
 'sec_center/overview':{code:0,meta:{insecure:2,total:5},config_scanner:{meta:{last_score:73}},log:{meta:{enable:1}}},
 'anti_attack/get_status':{code:0,scan:0,dos:0,rpfilter:0},
 'url_fw/get_status':{code:0,enable:1,auto_update:1},
 'url_fw/show_policy':{code:0,list:[{tag:'virus_download',name:'Вредоносные загрузки',policy:'reject'}]},
 'device_security/overview':{code:0,meta:{enable:0,total:3,protected:0}},
 'xqsystem/installed_plug':{code:0,data:{list:[{id:'fixture-hosts',name:'Пользовательский Hosts',version:'1.0.0',supportedByRom:true,status:0,use_status:0}]}},
 'xqsmarthome/request_smartcontroller':{code:0,scene_list:[{id:1,name:'График перезапуска',action_list:[{type:'normal_reboot'}],launch:{timer:{time:'04:00:00',repeat:'1,3,5',enabled:true}}}]},
 'xqsystem/device_mac':{code:0,mac:clients[0].mac},
 'xqnetwork/get_iotwifi_info':{code:0,basicInfo:[{ssid:'IoT 2g',encryption:'psk2',password:'not-a-real-network-key'},{ssid:'IoT 5g',encryption:'ccmp',password:'not-a-real-network-key'}],advanceInfo:{enable:0,wifi5mode:1,high_priority_access:0}},
 'xqnetwork/wifi_macfilter_info':{code:0,enable:0,model:0,macfilter:[],flist:clients},
 'xqnetwork/ipmac_check_status':{code:0,enable:0},'xqnetwork/get_gw_security':{code:0,enable:'0'},
 'xqnetwork/get_ipv6_firewall':{code:'1'},'xqnetwork/get_wps_info':{code:0,wps_enable:0,wpa3_only:1},
 'misystem/web_access_info':{code:0,open:false},
 'misystem/topo_graph':{code:0,show:0,graph:{hardware:'RD08',ip:'192.168.31.1',name:'Домашняя сеть',locale:'Гостиная'}},
 'misystem/child_mesh_infos':{code:0,childMeshInfos:[]},'misystem/get_mesh_bh_mode':{code:0,bhmode:'auto'},
 'xqnetwork/get_sta_bindinfo':{code:0,bindinfo:{bind_node:'none',bind_band:'none',bind_mac:'none'},meshnode:[{mac:'02:00:00:00:00:FE',router_name:'Главный роутер',support_accessCtl:1,wifiup:1}]},
 'misystem/mipctl_get_user_list':{code:0,user_list:[{user_id:1,user_name:'Семья',status:1}]},
 'misystem/mipctl_get_device_list':{code:0,list:[{user_id:1,devices:[clients[1].mac]}]},
 'misystem/mipctl_get_filting_net':{code:0,list:['example.net']},'misystem/mipctl_get_deny_time':{code:0,time_list:[]},
 'misystem/mipctl_get_temp_deny':{code:0,deny:false},'misystem/mipctl_get_app_antiaddict':{code:0,list:[{class_name:'Игры',enable:true,time_quota:120,app_list:[{name:'Игровое приложение',enable:true}]}]},
 'xqnetwork/get_port_state':{code:0,ports:[{label:'LAN1',speed:'1000'},{label:'LAN2',speed:'0'},{label:'LAN3',speed:'0'},{label:'LAN4',speed:'2500'}]},
 'xqnetwork/wan_speed':{code:0,speed:0},'xqnetwork/get_multiwan_dev_policies':{code:0,info:{dev_policies:[]}},
 'xqnetwork/wan_statistics':{code:0,download:500000,upload:30000},'misystem/router_info':{code:0,hardware:'RD08'},
 'misystem/feature_info':{wifi:{mlo:'1',iot_dev:'1',wifiguest:'1'},apps:{mipctlv2:'1',mipctlv2_temp_allow:'1'}},
 'xqnetwork/wifi_diag_detail_all':{code:0,info:[{ifname:'wl0',status:1},{ifname:'wl14',iftype:3,status:'0',ssid:'Гости',encryption:'psk2',password:'not-a-real-network-key'}]},
 'xqnetwork/get_wan6_switch_v2':{code:0,enabled:1},'misystem/smartvpn_info':{code:0,info:{switch:0,mode:0}},
 'xqnetwork/get_wifi_weak':{code:0,info:[{weakenable:'0',weakthreshold:'0',kickthreshold:'0'},{weakenable:'0',weakthreshold:'0',kickthreshold:'0'}]},
 'xqnetwork/ddns_get_server':{code:1614},
});
fixture['xqnetwork/wifi_detail_all'].info.forEach(x=>Object.assign(x,{ax:'1',txbf:'3'}));
