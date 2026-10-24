# Port coverage manifest for `mix opensafety.coverage`.
#
# Key: "File.c:Function", or "File.c:*" for every function in a file (an
# exact entry wins over the wildcard). Value: {status, elixir, note}, with
# status one of :ported, :partial, :replaced, :na. Unlisted functions are
# :missing. See Mix.Tasks.Opensafety.Coverage for what each status means.
#
# Classification rules used throughout:
#
#   * *_GetErrorStr: diagnostic string tables (EPLS_cfg_ERROR_STRING), :na.
#     Errors are atoms in the Elixir port.
#   * *_Get*Obj under "#pragma CTC SKIP": unit-test accessors, :na.
#   * SCFM: control-flow monitoring of the C build itself, :na.
#   * Pointer setup into the SOD, instance tables, frame-buffer plumbing:
#     :replaced when the Elixir design covers the purpose another way
#     (config maps, processes, binaries). Validation that came with them
#     and is not reproduced makes them :partial instead.

%{
  ## SFS - frame codec

  "SFSser.c:SFS_FrmSerialize" => {:ported, "OpenSafety.Frame.encode/3", nil},
  "SFSser.c:checkTxFrameHeader" => {:ported, "OpenSafety.Frame.check_tx/1", nil},
  "SFSdeser.c:SFS_FrmDeSerialize" =>
    {:ported, "OpenSafety.Frame.decode/3", "also rejects invalid frame IDs up front"},
  "SFSmain.c:SFS_ScmUdidCode" => {:ported, "OpenSafety.Frame.udid_code/3", nil},
  "SFSmain.c:SFS_Init" => {:replaced, nil, "no frame buffer pool; frames are binaries"},
  "SFSmain.c:SFS_GetMemBlock" => {:replaced, nil, "no frame buffer pool; frames are binaries"},
  "SFSmain.c:SFS_GetErrorStr" => {:na, nil, "diagnostic strings"},
  "SFScopy.c:SFS_NetworkCopyGen" => {:replaced, nil, "binary pattern matching"},

  ## SPDO - main

  "SPDOmain.c:SPDO_Init" =>
    {:ported, "OpenSafety.SPDO.init/1", "config: :sod; config: :options as an alternative"},
  "SPDOmain.c:SPDO_BuildTxSpdoIx" => {:ported, "OpenSafety.SPDO.build_one/3", nil},
  "SPDOmain.c:SPDO_ResetConnectionValidBitField" =>
    {:ported, "OpenSafety.SPDO.Rx.reset (cv)", "bit kept per Rx SPDO; conn_valid/1 joins"},
  "SPDOmain.c:SPDO_CheckRxTimeout" => {:ported, "OpenSafety.SPDO.check_timeout/2", nil},
  "SPDOmain.c:SPDO_BuildTxSpdo" => {:ported, "OpenSafety.SPDO.build/3", "three passes, C order"},
  "SPDOmain.c:SPDO_ProcessRxSpdo" =>
    {:ported, "OpenSafety.SPDO.process/3", "pre-operational skips the SDN check"},
  "SPDOmain.c:SPDO_TxDataChanged" =>
    {:ported, "OpenSafety.SPDO.data_changed/2", "put_data/3 for config: :options"},
  "SPDOmain.c:SPDO_SetToOp" => {:ported, "OpenSafety.SPDO :pre_operational -> :operational", nil},
  "SPDOmain.c:SPDO_SetToPreOp" =>
    {:ported, "OpenSafety.SPDO :operational -> :pre_operational", nil},
  "SPDOmain.c:ProcessTReq" => {:ported, "OpenSafety.SPDO.dispatch/3", nil},
  "SPDOmain.c:ProcessTRes" => {:ported, "OpenSafety.SPDO.Rx (tres)", nil},
  "SPDOmain.c:SPDO_GetErrorStr" => {:na, nil, "diagnostic strings"},
  "SPDOmain.c:SPDO_GetMainObj" => {:na, nil, "unit-test accessor"},

  ## SPDO - address assignment

  "SPDOassign.c:SPDO_InitAssign" => {:replaced, nil, "address lookup over the SPDO lists"},
  "SPDOassign.c:SPDO_AddSAdr" => {:ported, "OpenSafety.SPDO.activate_mapping/1", nil},
  "SPDOassign.c:SPDO_AddTAdr" => {:ported, "OpenSafety.SPDO.activate_mapping/1", nil},
  "SPDOassign.c:SPDO_GetSpdoIdxForSAdr" => {:ported, "OpenSafety.SPDO.rx_call/3", nil},
  "SPDOassign.c:SPDO_GetSpdoIdxForTAdr" => {:ported, "OpenSafety.SPDO.dispatch/3", nil},
  "SPDOassign.c:SPDO_GetNoProcRxSpdo" => {:replaced, nil, "list length"},
  "SPDOassign.c:SPDO_GetNoProcTxSpdo" => {:replaced, nil, "list length"},

  ## SPDO - initialization from the SOD

  "SPDOinit.c:SPDO_InitAll" => {:ported, "OpenSafety.SPDO.Config.init/1", nil},
  "SPDOinit.c:InitTxSpdo" => {:ported, "OpenSafety.SPDO.Config.scan/7", nil},
  "SPDOinit.c:TxMappCommInit" => {:ported, "OpenSafety.SPDO.Config.spdo_init/5", nil},
  "SPDOinit.c:InitRxSpdo" => {:ported, "OpenSafety.SPDO.Config.scan/7", nil},
  "SPDOinit.c:RxMappCommInit" => {:ported, "OpenSafety.SPDO.Config.spdo_init/5", nil},

  ## SPDO - Rx consumer

  "SPDOrxConsSm.c:SPDO_ConsSmConnect" =>
    {:ported, "OpenSafety.SPDO.activate_rx/2", "connections kept in :conn"},
  "SPDOrxConsSm.c:SPDO_ConsSmInit" => {:replaced, "OpenSafety.SPDO.Rx.init/1", nil},
  "SPDOrxConsSm.c:SPDO_ConsSmResetRx" => {:ported, "OpenSafety.SPDO.Rx.reset_data/1", nil},
  "SPDOrxConsSm.c:SPDO_ConsSmTimeSyncSucceeded" =>
    {:ported, "OpenSafety.SPDO.Rx.accept_tres/3", nil},
  "SPDOrxConsSm.c:SPDO_ConsSm" =>
    {:ported, "OpenSafety.SPDO.Rx.cons_sm/4", nil},
  "SPDOrxConsSm.c:SPDO_CtValid" => {:ported, "OpenSafety.SPDO.Rx.ct_valid?/2", nil},
  "SPDOrxConsSm.c:ProcessData" => {:ported, "OpenSafety.SPDO.Rx.process_data/3", nil},
  "SPDOrxConsSm.c:SPDO_GetRxSpdoStatus" => {:ported, "OpenSafety.SPDO.rx_status/3", nil},
  "SPDOrxConsSm.c:SPDO_GetRxConsSmObj" => {:na, nil, "unit-test accessor"},

  ## SPDO - Rx time synchronization consumer

  "SPDOrxSyncConsSm.c:SPDO_InitRxSyncCons" => {:na, nil, "multi-instance pointer table"},
  "SPDOrxSyncConsSm.c:SPDO_GetTxSpdoNo" => {:replaced, "Rx config :tx_spdo_no", nil},
  "SPDOrxSyncConsSm.c:SPDO_SetPtrToRxCommPara" =>
    {:ported, "OpenSafety.SPDO.Config.comm_para/3", "values re-read at activation"},
  "SPDOrxSyncConsSm.c:SetPtrToRxCommPara" =>
    {:ported, "OpenSafety.SPDO.Config.comm_value/4", nil},
  "SPDOrxSyncConsSm.c:SPDO_ResetRxSm" => {:ported, "OpenSafety.SPDO.reset_rx/1", nil},
  "SPDOrxSyncConsSm.c:SPDO_CheckRxCommPara" =>
    {:ported, "OpenSafety.SPDO.activate_mapping/1", nil},
  "SPDOrxSyncConsSm.c:SPDO_TimeSyncConsSm" => {:ported, "OpenSafety.SPDO.Rx states", nil},
  "SPDOrxSyncConsSm.c:TimeSyncConsSmInit" => {:ported, "OpenSafety.SPDO.Rx.reset_data/1", nil},
  "SPDOrxSyncConsSm.c:StateWaitForTres" => {:ported, "OpenSafety.SPDO.Rx :wf_tres", nil},
  "SPDOrxSyncConsSm.c:IsTrValid" => {:ported, "OpenSafety.SPDO.Rx.tr_valid?/3", nil},
  "SPDOrxSyncConsSm.c:IncTReqCounters" => {:ported, "OpenSafety.SPDO.Rx.inc_treq/2", nil},
  "SPDOrxSyncConsSm.c:SPDO_GetRxSyncConsSmObj" => {:na, nil, "unit-test accessor"},

  ## SPDO - mapping

  "SPDOrxmapp.c:SPDO_RxMappingProcess" =>
    {:ported, "OpenSafety.SPDO.Rx.map_data/2", "config: :sod"},
  "SPDOrxmapp.c:SPDO_RxSpdoToSafeState" => {:ported, "OpenSafety.SPDO.Rx.to_safe/1", nil},
  "SPDOtxmapp.c:SPDO_TxMappingProcess" =>
    {:ported, "OpenSafety.SPDO.Tx.payload/1", "config: :sod"},

  ## SPDO - Tx producer

  "SPDOtxProdSm.c:SPDO_ClearConnectedRxSpdo" => {:replaced, "OpenSafety.SPDO.conn_valid?/2", nil},
  "SPDOtxProdSm.c:SPDO_SyncOkConnect" => {:replaced, "OpenSafety.SPDO.conn_valid?/2", nil},
  "SPDOtxProdSm.c:SPDO_InitTxSm" => {:replaced, "OpenSafety.SPDO.Tx.init/1", nil},
  "SPDOtxProdSm.c:SPDO_SetPtrToTxCommPara" =>
    {:ported, "OpenSafety.SPDO.Config.comm_para/3", "values re-read at activation"},
  "SPDOtxProdSm.c:SetPtrToTxCommPara" => {:ported, "OpenSafety.SPDO.Config.comm_value/4", nil},
  "SPDOtxProdSm.c:SPDO_ResetTxSm" => {:ported, "OpenSafety.SPDO.Tx.reset/2", nil},
  "SPDOtxProdSm.c:SPDO_CheckTxCommPara" => {:ported, "OpenSafety.SPDO.activate_mapping/1", nil},
  "SPDOtxProdSm.c:SPDO_ProdSm" => {:ported, "OpenSafety.SPDO.Tx.build_data/4", nil},
  "SPDOtxProdSm.c:SPDO_SendTxSpdo" => {:ported, "OpenSafety.SPDO.Tx.send/7", nil},
  "SPDOtxProdSm.c:SendTxSpdo" => {:ported, "OpenSafety.SPDO.Tx.send/7", nil},
  "SPDOtxProdSm.c:SPDO_TxSpdoIdxExists" => {:ported, "OpenSafety.SPDO.tx_exists/2", nil},
  "SPDOtxProdSm.c:SPDO_NewData" => {:ported, "OpenSafety.SPDO.Tx.data_changed/1", nil},
  "SPDOtxProdSm.c:GetConnectionValid" => {:ported, "OpenSafety.SPDO.conn_valid?/2", nil},
  "SPDOtxProdSm.c:SPDO_GetTxProdSmObj" => {:na, nil, "unit-test accessor"},

  ## SPDO - Tx time synchronization producer

  "SPDOtxSyncProdSm.c:SPDO_TimeSyncProdSmReset" => {:ported, "OpenSafety.SPDO.Tx.reset/2", nil},
  "SPDOtxSyncProdSm.c:SPDO_TimeSyncProdSmNoTresSet" => {:replaced, "Tx config :no_tres", nil},
  "SPDOtxSyncProdSm.c:SPDO_TimeSyncProdSm" => {:ported, "OpenSafety.SPDO.Tx states", nil},
  "SPDOtxSyncProdSm.c:SPDO_GetTxSyncProdSmObj" => {:na, nil, "unit-test accessor"},

  ## SDN

  "SDNmain.c:SDN_Init" =>
    {:ported, "OpenSafety.Node.check_sdn/1", "SDN then read from the SOD on each use"},
  "SDNmain.c:SDN_GetSdn" => {:ported, "SOD 0x1200/1 via SPDO, SNMTS, SSDOS", nil},
  "SDNmain.c:SDN_SetSdn" => {:ported, "OpenSafety.SNMTS :wf_sadr_ass_step2", nil},
  "SDNmain.c:getCheckSdn" => {:ported, "OpenSafety.Node.check_sdn/1", nil},
  "SDNmain.c:SDN_GetErrorStr" => {:na, nil, "diagnostic strings"},

  ## SOD

  "SODmain.c:SOD_Init" => {:ported, "OpenSafety.SOD.new/1", nil},
  "SODmain.c:SOD_Read" => {:ported, "OpenSafety.SOD.read/4", nil},
  "SODmain.c:SOD_Write" => {:ported, "OpenSafety.SOD.write/6", "also checks the data length"},
  "SODmain.c:SetDefaultValues" => {:ported, "OpenSafety.SOD.set_defaults/1", nil},
  "SODmain.c:ObjectReadOnly" => {:ported, "OpenSafety.SOD.read_only_same?/3", nil},
  "SODmain.c:ObjectWriteable" => {:ported, "OpenSafety.SOD.object_writeable/2", nil},
  "SODmain.c:VisibleStringCheck" => {:ported, "OpenSafety.SOD.visible_string_check/1", nil},
  "SODmain.c:DataValid" => {:ported, "OpenSafety.SOD.data_valid/4", nil},
  "SODmain.c:CallBeforeReadClbk" => {:ported, "OpenSafety.SOD.callback/7", nil},
  "SODmain.c:CallBeforeWriteClbk" => {:ported, "OpenSafety.SOD.callback/7", nil},
  "SODmain.c:CallAfterWriteClbk" => {:ported, "OpenSafety.SOD.after_write/3", nil},
  "SODmain.c:DataCpy" => {:ported, "OpenSafety.SOD.data_cpy/4", nil},
  "SODattr.c:SOD_InitAddr" => {:replaced, "OpenSafety.SOD.new/1", "map, not a sorted table"},
  "SODattr.c:SOD_AttrGet" => {:ported, "OpenSafety.SOD.attr_get/3", nil},
  "SODattr.c:SOD_AttrGetNext" => {:ported, "OpenSafety.SOD.attr_next/2", "cursor passed in"},
  "SODattr.c:SOD_HdlValid" => {:replaced, "OpenSafety.SOD.fetch/2", "handle is the key"},
  "SODattr.c:SOD_GetSodStartAddr" => {:replaced, nil, "no table address"},
  "SODattr.c:SearchObject" => {:replaced, "map lookup", "binary search over a pointer table"},
  "SODcheck.c:SOD_Check" => {:ported, "OpenSafety.SOD.check_all/2", "order not required"},
  "SODcheck.c:AttrCheck" => {:ported, "OpenSafety.SOD.attr_check/1", nil},
  "SODcheck.c:DataTypeCheck" => {:ported, "OpenSafety.SOD.data_type_check/1", nil},
  "SODcheck.c:DataPointerCheck" => {:na, nil, "C data pointers"},
  "SODlock.c:*" => {:ported, "OpenSafety.SOD lock / write enable", nil},
  "SODactLen.c:*" => {:ported, "OpenSafety.SOD.act_len_set/3, act_len_get/2", nil},

  ## SNMTS

  "SNMTSmain.c:SNMTS_Init" => {:replaced, "OpenSafety.SNMTS.init/1", "objects resolved per use"},
  "SNMTSmain.c:SNMTS_TimerCheck" => {:ported, "OpenSafety.SNMTS.timer_check/3", nil},
  "SNMTSmain.c:SNMTS_PassParamChkSumValid" =>
    {:ported, "OpenSafety.SNMTS.pass_param_chksum_valid/2", nil},
  "SNMTSmain.c:SNMTS_EnterOpState" => {:ported, "OpenSafety.SNMTS.enter_op_state/4", nil},
  "SNMTSmain.c:SNMTS_PerformTransPreOp" =>
    {:ported, "OpenSafety.SNMTS.perform_trans_pre_op/2", nil},
  "SNMTSprocess.c:SNMTS_InitParamUdid" => {:replaced, nil, "UDID read from 0x1019 per use"},
  "SNMTSprocess.c:SNMTS_ProcessRequest" => {:ported, "OpenSafety.SNMTS.process_request/3", nil},
  "SNMTSprocess.c:processRequest" => {:ported, "OpenSafety.SNMTS.process_request_frame/4", nil},
  "SNMTSprocess.c:processRequestExt" =>
    {:ported, "OpenSafety.SNMTS.process_request_ext/4", "SCM SET TO STOP/OP with :scm"},
  "SNMTSprocess.c:checkRequest" => {:ported, "OpenSafety.SNMTS.check_request/2", nil},
  "SNMTSprocess.c:filterServReq" => {:ported, "OpenSafety.SNMTS.filter_serv_req/2", nil},
  "SNMTSprocess.c:checkRxUdid" => {:ported, "OpenSafety.SNMTS.check_rx_udid/2", nil},
  "SNMTSsnstate.c:*" => {:ported, "OpenSafety.SNMTS states", nil},
  "SNMTSsnstate.c:checkParam" => {:na, nil, "NULL buffer checks"},
  "SNMTSresponse.c:*" => {:ported, "OpenSafety.SNMTS responses", nil},
  "SNMTSresponse.c:SNMTS_SodAcsInit" => {:replaced, nil, "objects resolved per use"},
  "SNMTSresponse.c:MainSadrAcsInit" => {:replaced, nil, "objects resolved per use"},
  "SNMTSresponse.c:UdidScmAcsInit" => {:replaced, nil, "objects resolved per use"},
  "SNMTSappInfo.c:*" => {:ported, "OpenSafety.SNMTS app info", nil},
  "SNMTSappInfo.c:SNMTS_AppInfoInit" => {:replaced, nil, "objects resolved per use"},
  "SNMTSlifetime.c:*" => {:ported, "OpenSafety.SNMTS life guarding", nil},
  "SNMTSlifetime.c:SNMTS_LifeTimeInit" => {:replaced, nil, "objects resolved per use"},
  "SNMTSrefresh.c:*" => {:ported, "OpenSafety.SNMTS refresh", nil},
  "SNMTSrefresh.c:SNMTS_RefreshTimeInit" => {:replaced, nil, "objects resolved per use"},

  ## SSDOS

  "SSDOSmain.c:*" => {:ported, "OpenSafety.SSDOS states", nil},
  "SSDOSmain.c:SSDOS_Init" => {:replaced, "OpenSafety.SSDOS.init/1", "main SADR read per use"},
  "SSDOSsodAcs.c:*" => {:ported, "OpenSafety.SSDOS SOD access", nil},
  "SSDOSsodAcs.c:SSDOS_SodAcsWriteAllowed" =>
    {:ported, "OpenSafety.SSDOS.write_allowed/2", "single instance (no shared objects)"},
  "SSDOSupDnwLd.c:*" => {:ported, "OpenSafety.SSDOS up/download", nil},

  ## SSC

  "SSCmain.c:SSC_InitAll" => {:ported, "OpenSafety.Node.init/1", nil},
  "SSCmain.c:initInst" => {:ported, "OpenSafety.Node.init/1", nil},
  "SSCprocess.c:SSC_ProcessSNMTSSDOFrame" =>
    {:ported, "OpenSafety.Node.process/3", "busy loop inside SNMTS/SSDOS calls"},
  "SSCprocess.c:SSC_InitFsm" => {:replaced, nil, "no shared rx/tx buffers"},
  "SSCprocess.c:processStateDeSer" => {:ported, "OpenSafety.Node :process", nil},
  "SSCprocess.c:processStateReqProc" => {:ported, "OpenSafety.Node.dispatch/3", nil},
  "SSCprocess.c:processStateSer" =>
    {:ported, "OpenSafety.Node.encode/2", "slim bit set in SSDOS"},

  ## SPDO mapping activation (driven by SNMTS)

  "SPDOmain.c:SPDO_ActivateStart" => {:replaced, nil, "activation is a single call"},
  "SPDOmain.c:SPDO_ActivateTxSpdoMapping" =>
    {:ported, "OpenSafety.SPDO.activate_tx/1", "mapping via OpenSafety.SPDO.Config.activate/3"},
  "SPDOmain.c:SPDO_ActivateRxSpdoMapping" =>
    {:ported, "OpenSafety.SPDO.activate_rx/2", "mapping via OpenSafety.SPDO.Config.activate/3"},

  ## SNMTM - SNMT master (a GenServer pool; callbacks returned as effects)

  "SNMTMfsm.c:*" => {:ported, "OpenSafety.SNMTM", nil},
  "SNMTMfsm.c:SNMTM_InitFsm" => {:replaced, "OpenSafety.SNMTM.init/1", "SOD read on use"},
  "SNMTMfsm.c:processTimeoutChk" => {:ported, "OpenSafety.SNMTM.build/6", nil},
  "SNMTMrequest.c:*" => {:ported, "OpenSafety.SNMTM req_*/sn_error_ack", nil},
  "SNMTMmain.c:SNMTM_Init" => {:replaced, "OpenSafety.SNMTM.init/1", "SOD read on use"},
  "SNMTMmain.c:SNMTM_BuildRequest" => {:ported, "OpenSafety.SNMTM.build_request/3", nil},
  "SNMTMmain.c:SNMTM_ProcessResponse" =>
    {:ported, "OpenSafety.SNMTM.process_response/3", "callbacks as effects"},
  "SNMTMmain.c:IsDsadrScmSadr" => {:ported, "OpenSafety.SNMTM.dsadr_scm_sadr?/2", nil},

  ## SSDOC - SSDO client (a GenServer pool; callbacks returned as effects)

  "SSDOCaccess.c:SSDOC_Init" => {:replaced, "OpenSafety.SSDOC.init/1", nil},
  "SSDOCaccess.c:SSDOC_SendWriteReq" => {:ported, "OpenSafety.SSDOC.send_write_req/6", nil},
  "SSDOCaccess.c:SSDOC_SendReadReq" => {:ported, "OpenSafety.SSDOC.send_read_req/5", nil},
  "SSDOCaccess.c:TypeLenReadValid" => {:ported, "OpenSafety.SSDOC.type_len_read_valid/4", nil},
  "SSDOCaccess.c:TypeLenValid" => {:ported, "OpenSafety.SSDOC.type_len_valid/4", nil},
  "SSDOCprotocol.c:*" => {:ported, "OpenSafety.SSDOC protocol layer", nil},
  "SSDOCprotocol.c:SSDOC_ProtocolLayerInit" => {:replaced, "OpenSafety.SSDOC.init/1", nil},
  "SSDOCservTimer.c:*" => {:ported, "OpenSafety.SSDOC serv_req/build", nil},
  "SSDOCservTimer.c:SSDOC_TimerInit" => {:replaced, "OpenSafety.SSDOC.init/1", "SOD read on use"},
  "SSDOCservTimer.c:SSDOC_TimerCheck" => {:ported, "OpenSafety.SSDOC.build/5", nil},
  "SSDOCservice.c:*" => {:ported, "OpenSafety.SSDOC service layer", nil},
  "SSDOCservice.c:SSDOC_ServiceFsmInit" => {:replaced, "OpenSafety.SSDOC.init/1", nil},
  "SSDOCservice.c:SSDOC_GetReqBuffer" => {:replaced, nil, "request buffer is slot data"},
  "SSDOCservice.c:reqBufferSend" => {:ported, "OpenSafety.SSDOC.req_frame/1", nil},
  "SSDOCservreq.c:*" => {:ported, "OpenSafety.SSDOC service requests", nil},
  "SSDOCservreq.c:SSDOC_ServiceLayerInit" => {:replaced, "OpenSafety.SSDOC.init/1", nil},

  ## SCM - coordinator (gen_statem :stopped/:active) and per-SN gen_statem

  "SCMmain.c:SCM_Init" => {:ported, "OpenSafety.SCM.init/1", nil},
  "SCMmain.c:SCM_Trigger" => {:ported, "OpenSafety.SCM.tick/3", nil},
  "SCMmain.c:SCM_Activate" =>
    {:ported, "OpenSafety.SCM.activate/1", "stays :stopped when init fails"},
  "SCMmain.c:SCM_Deactivate" => {:ported, "OpenSafety.SCM.deactivate/1", nil},
  "SCMmain.c:SCM_ResetNodeGuarding" => {:ported, "OpenSafety.SCM.reset_node_guarding/1", nil},
  "SCMmain.c:SCM_OperatorAck" => {:ported, "OpenSafety.SCM.operator_ack/2", nil},
  "SCMmain.c:SCM_SnFailAck" => {:ported, "OpenSafety.SCM.sn_fail_ack/4", nil},
  "SCMmain.c:SCM_SNMTM_ResetGuardClbk" =>
    {:ported, "OpenSafety.SCM.SN :reset_guard_clbk", "delivered as effect"},
  "SCMmain.c:SCM_UniqueUdid" => {:ported, "OpenSafety.SCM.SN.unique_udid?/2", "asks peers"},
  "SCMmain.c:ScmInitFsm" => {:ported, "OpenSafety.SCM.init_fsm/1", nil},
  "SCMmain.c:SnSodEntryInit" => {:ported, "OpenSafety.SCM.sn_entries/3", nil},
  "SCMmain.c:CheckTimeout" => {:ported, "OpenSafety.SCM.SN.check_timeout/3", nil},
  "SCMmain.c:ScmFsmPreCon" => {:ported, "OpenSafety.SCM.SN.precon?/3", nil},
  "SCMmain.c:ScmFsmProcess" => {:ported, "OpenSafety.SCM.SN.process/3", nil},
  "SCMbase.c:SCM_SNMTM_RespClbk" => {:ported, "OpenSafety.SCM.SN.deliver/2", nil},
  "SCMbase.c:SCM_SsdocClbk" => {:ported, "OpenSafety.SCM.SN.deliver/2", nil},
  "SCMbase.c:SCM_SodRead" => {:ported, "OpenSafety.SCM.SN.sod_get/3", nil},
  "SCMbase.c:SCM_SodGetActLen" => {:ported, "OpenSafety.SCM.SN.act_len/2", nil},
  "SCMbase.c:SCM_SodPtrAcs" => {:ported, "OpenSafety.SCM.ptr_acs/3", "check only; access by handle"},
  "SCMbase.c:SCM_SodQueryRead" => {:ported, "OpenSafety.SCM(.SN).query_read/3", nil},
  "SCMbase.c:SCM_SodWrite" => {:ported, "OpenSafety.SCM.SN.set_status/3", "its only use"},
  "SCMbase.c:SCM_SetNodeStatus" => {:ported, "OpenSafety.SCM.SN.set_status/3", nil},
  "SCMbase.c:SCM_BuildLocalSadrList" => {:ported, "OpenSafety.SCM.local_sadr_list/1", nil},
  "SCMbase.c:SCM_GetNextAddSadr" => {:ported, "OpenSafety.SCM.SN.next_add_sadr/3", nil},
  "SCMbase.c:SCM_NumFreeFrmsSet" => {:replaced, nil, "free count threaded through calls"},
  "SCMbase.c:SCM_NumFreeFrmsDec" => {:replaced, "OpenSafety.SCM.SN.sent/2", nil},
  "SCMoper.c:*" => {:ported, "OpenSafety.SCM.SN states", nil},
  "SCMudidMism.c:*" => {:ported, "OpenSafety.SCM.SN states", nil},
  "SCMverDvi.c:*" => {:ported, "OpenSafety.SCM.SN states", nil},
  "SCMverParam.c:*" => {:ported, "OpenSafety.SCM.SN states", nil},
  "SCMdldParam.c:*" => {:ported, "OpenSafety.SCM.SN states", nil},
  "SCMdldAddParam.c:*" => {:ported, "OpenSafety.SCM.SN states", nil},
  "SCMactSn.c:*" => {:ported, "OpenSafety.SCM.SN states", nil},
  "SCMguarding.c:*" => {:ported, "OpenSafety.SCM.SN states", nil},

  ## SERR

  "SERRmain.c:SERR_Init" => {:replaced, nil, "errors are events"},
  "SERRmain.c:SERR_SetError" => {:replaced, "{:error, code, info} events", nil},
  "SERRmain.c:SERR_GetLastAddInfo" => {:replaced, "{:error, code, info} events", nil},
  "SERRmain.c:SERR_GetErrorStr" => {:na, nil, "diagnostic strings"},
  "SERRmain.c:SERR_CountCommonEvt" => {:ported, "OpenSafety.SERR.count_common/2", nil},
  "SERRmain.c:SERR_CountSpdoEvt" => {:ported, "OpenSafety.SERR.count_spdo/3", nil},
  "SERRmain.c:SERR_CountAcycEvt" => {:ported, "OpenSafety.SERR.count_acyc/3", nil},
  "SERRmain.c:SERR_GetSpdoStatCtr" => {:ported, "OpenSafety.SERR.get_spdo/3", nil},
  "SERRmain.c:SERR_GetAcycStatCtr" => {:ported, "OpenSafety.SERR.get_acyc/3", nil},
  "SERRmain.c:SERR_GetCommonStatCtr" => {:ported, "OpenSafety.SERR.get_common/2", nil},

  ## SCFM - control-flow monitoring

  "SCFMmain.c:*" => {:na, nil, "control-flow monitoring of the C build"},

  ## Diagnostic strings and unit-test accessors elsewhere

  "SNMTSmain.c:SNMTS_GetErrorStr" => {:na, nil, "diagnostic strings"},
  "SODmain.c:SOD_GetErrorStr" => {:na, nil, "diagnostic strings"},
  "SSCmain.c:SSC_GetErrorStr" => {:na, nil, "diagnostic strings"},
  "SSDOSmain.c:SSDOS_GetErrorStr" => {:na, nil, "diagnostic strings"},
  "SCMmain.c:SCM_GetErrorStr" => {:na, nil, "diagnostic strings"},
  "SNMTMmain.c:SNMTM_GetErrorStr" => {:na, nil, "diagnostic strings"},
  "SSDOCaccess.c:SSDOC_GetErrorStr" => {:na, nil, "diagnostic strings"},
  "SCMmain.c:SCM_GetPtrTo_w_SnRealNum" =>
    {:na, nil, "unit-test accessor (doc: only used for testing)"},
  "SCMmain.c:SCM_GetFsmStateFunctionsPtr" =>
    {:na, nil, "unit-test accessor (doc: only used for testing)"}
}
