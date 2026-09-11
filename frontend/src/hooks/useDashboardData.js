import {useCallback,useEffect,useState} from 'react'
import {getDashboard} from '../services/api'
import {connectDashboardSocket} from '../services/websocket'

export function useDashboardData(){
  const [data,setData]=useState(null), [connection,setConnection]=useState('CONNECTING'), [error,setError]=useState('')
  const refresh=useCallback(async()=>{try{setError('');setData(await getDashboard())}catch(e){setError(e.message)}},[])
  useEffect(()=>{
    refresh()
    return connectDashboardSocket({onData:d=>{setData(d);setError('')},onStatus:setConnection})
  },[refresh])
  return {data,connection,error,retry:refresh}
}
