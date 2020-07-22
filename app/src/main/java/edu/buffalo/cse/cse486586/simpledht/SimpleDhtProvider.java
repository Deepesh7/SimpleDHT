package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDhtProvider extends ContentProvider {

    public final String AVD0_PORT = "11108";
    static final int SERVER_PORT = 10000;
    String hashVal = "";
    String PREDECESSOR = "";
    String SUCCESSOR = "";
    String myPort = "";
    String recieved_val = "-1";
    String star_text = "";
    boolean star_res = false;
    static final String[] REMOTE_PORTS = new String[] {"11108","11112","11116","11120","11124"};
    HashMap<String,String> hash_node_map = new HashMap<String, String>();
    boolean correct_destination = false;
    HashMap<String,String> data = new HashMap<String, String>();

    ArrayList<String> online_ports = new ArrayList<String>();

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub

        if(online_ports.size() == 1){
            if(selection.equals("*") || selection.equals("@")){
                for (String key : data.keySet()) {
                    Log.i("Hello key: ",key);
                    data.remove(key);
                }
                return 0;
            }
            else{
                data.remove(selection);
            }
        }
        else{
            if(selection.equals("@")){
                for (String key : data.keySet()) {
                    Log.i("Hello key: ",key);
                    data.remove(key);
                }
            }
            else if(selection.equals("*")){}
            else {
                String val = data.remove(selection);
                if(val == null){
                    String msgToSend = "DELETE "+selection+" "+myPort;
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msgToSend);
                }
            }
        }

        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub
        // Current node has all the values
        String kh = "";
        correct_destination = false;
        if(online_ports.size() == 1){
            correct_destination = true;
        }
        else{
            try {
                String key = String.valueOf(values.get("key"));
                String value = String.valueOf(values.get("value"));
                String key_hash = genHash(key);
                kh = key_hash;
                Log.i("insert","hash: " + key_hash + "key: "+key);
                // Files hash is greater than Node's Hash
                if(key_hash.compareTo(hashVal) > 0){
                    Log.i("insert","hash: " + key_hash + " key: "+key + " is greater than my hash");
                    // Predecessor's nodes is greater than current node. Only happens when this node has the lowest hashval
                    if(PREDECESSOR.compareTo(hashVal) > 0 && key_hash.compareTo(PREDECESSOR) > 0){
                        Log.i("insert","hash: " + key_hash + "key: "+key + "is the highest hash. so insert in my hash");
                        correct_destination = true;
                    }
                    else{
                        Log.i("Hello",key_hash + "is greater than mine");
                        String msgToSend = "INSERT "+ key + "_" + value;
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msgToSend);
                    }
                }
                // Files hash is less than equal to current node's hash
                else if(key_hash.compareTo(hashVal) <= 0){
                    Log.i("insert","hash: " + key_hash + " key: "+key + " is less than equal to my hash");
                    // Files hash is greater than predecessor's hash. i.e File's hash is between Predecessor and current node.
                    // File should be stored in current node.
                    if(key_hash.compareTo(PREDECESSOR) > 0 || hashVal.compareTo(PREDECESSOR) < 0){
                        correct_destination = true;
                    }
                    else{
                        Log.i("insert","hash: " + key_hash + " key: "+key + " is less than mine and my Pred.");
                        String msgToSend = "INSERT "+ key + "_" + value;
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msgToSend);
                    }

                }
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }

        if(correct_destination){
            data.put(values.get("key").toString(),values.get("value").toString());
            Log.i("insert","key: "+values.get("key").toString() + "insering in current node" );
            Log.v("insert", values.toString());
            return uri;
        }



        return null;
    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub


        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            Log.e("Hello", "Can't create a ServerSocket");
        }

        TelephonyManager tel = (TelephonyManager)this.getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        Log.i("Hello",portStr);

        myPort = String.valueOf((Integer.parseInt(portStr) * 2));

        Log.i("Hello",myPort);

        try {
            hashVal = genHash(portStr);
            PREDECESSOR = hashVal;
            SUCCESSOR = hashVal;
            hash_node_map.put(hashVal,myPort);
            Log.i("Hello","Pred: "+PREDECESSOR+" Succ: "+SUCCESSOR);
            online_ports.add(hashVal);
            Log.i("My hash",hashVal);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }



        if(! portStr.equals("5554")){
            Log.i("Hello","Not avd0");
            String msg = "join "+hashVal+"@"+myPort;
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg);
        }



        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {
        // TODO Auto-generated method stub

        String colnames[] = new String[] {"key","value"};
        MatrixCursor matrixCursor = new MatrixCursor(colnames);

        if(online_ports.size() == 1){
            if(selection.equals("*") || selection.equals("@")){
                for (String key : data.keySet()) {
                    Log.i("Hello key: ",key);
                    String val = data.get(key);
                    matrixCursor.addRow(new Object[]{key, val});
                }
                return matrixCursor;
            }
            String val = data.get(selection);
            matrixCursor.addRow(new Object[]{selection, val});

            return matrixCursor;
        }
        else{
            if(selection.equals("@")){
                for (String key : data.keySet()) {
                    Log.i("insert returning key: ",key);
                    String val = data.get(key);
                    matrixCursor.addRow(new Object[] {key, val});
                }
                return matrixCursor;
            }
            else if(selection.equals("*")){
                for(String key: data.keySet()){
                    String val = data.get(key);
                    matrixCursor.addRow(new Object[]{key,val});
                }
                String msgToSend = "QUERY * " + myPort + " ";
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msgToSend);
                while(! star_res ){ }

                if(! star_text.equals("")) {
                    try {
                        String arr[] = star_text.split("_");
                        for (int i = 0; i < arr.length; i++) {
                            String[] key_val = arr[i].split("@");
                            matrixCursor.addRow(new Object[]{key_val[0], key_val[1]});

                        }
                    }catch (Exception e){Log.i("query","Error occured from the star_text val");}
                }

                return matrixCursor;

            }
            else{
                recieved_val = data.get(selection);
                if(recieved_val == null){
                    Log.i("query","not in my node");
                    String msgToSend = "QUERY " + selection + "_" + myPort;
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msgToSend);
                    recieved_val = "-1";
                     while(recieved_val.equals("-1")){ }

                     matrixCursor.addRow(new Object[]{selection,recieved_val});
                }
                else{
                    matrixCursor.addRow(new Object[]{selection,recieved_val});
                }
                return matrixCursor;
            }

        }

        //return null;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private Uri buildUri(String scheme, String authority) {
        Uri.Builder uriBuilder = new Uri.Builder();
        uriBuilder.authority(authority);
        uriBuilder.scheme(scheme);
        return uriBuilder.build();
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    private void calcPredSucc(){
        int pred_index=0;
        int succ_index=0;
        for(int i=0;i<online_ports.size();i++){
            if(online_ports.get(i).equals(hashVal)){
                pred_index = i-1;
                if(pred_index == -1){
                    pred_index = online_ports.size() - 1;
                }
                succ_index = (i+1)%(online_ports.size());
                break;
            }
        }
        PREDECESSOR = online_ports.get(pred_index);
        SUCCESSOR = online_ports.get(succ_index);

    }


    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];
            /*
             * TODO: Fill in your server code that receives messages and passes them
             * to onProgressUpdate().
             */
            try {
                while(true){
                    Socket s = serverSocket.accept();
                    ObjectInputStream in = new ObjectInputStream(s.getInputStream());
                    String msg = String.valueOf(in.readObject());
                    Log.i("Hello recieved message",msg);
                    String[] msgs = msg.split(" ");

                    if(msgs[0].equals("join")) {
                        Log.i("Hello","join message recieved" + msgs[1]);
                        String[] node_hash = msgs[1].split("@");
                        String hash = node_hash[0];
                        String node = node_hash[1];
                        if (!online_ports.contains(hash)) {
                            online_ports.add(hash);
                            Collections.sort(online_ports);
                            hash_node_map.put(hash,node);
                            Log.i("Hello sorted ports", online_ports.toString());
                            calcPredSucc();
                            Log.i("Hello", "Pred: " + PREDECESSOR + " Succ: " + SUCCESSOR);
                            Log.i("Hello","Pred: " + hash_node_map.get(PREDECESSOR) + "Succ: " + hash_node_map.get(SUCCESSOR));

                            String msgToSend = "Sorted_Nodes ";//+ online_ports.toString();
                            for (int j = 0; j < online_ports.size(); j++) {
                                if (j == online_ports.size() - 1) {
                                    String h = online_ports.get(j);
                                    String p = hash_node_map.get(h);
                                    msgToSend = msgToSend + h + "@" + p;
                                } else {
                                    String h = online_ports.get(j);
                                    String p = hash_node_map.get(h);
                                    msgToSend = msgToSend + h + "@" + p + "_";
                                }
                            }

                            Log.i("Hello send sorted list",msgToSend);
                            for (int i = 1; i < 5; i++) {
                                try {
                                    Log.i("Hello ","sorted list sending to" + REMOTE_PORTS[i]);
                                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                            Integer.parseInt(REMOTE_PORTS[i]));
                                    ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                                    out.writeObject(String.valueOf(msgToSend));
                                    Log.i("Hello ","sorted list sent to" + REMOTE_PORTS[i]);
                                    out.close();
                                    //socket.close();
                                } catch (Exception e) {
                                    continue;
                                }
                            }
                        }
                    }
                    if(msgs[0].equals("Sorted_Nodes")){
                        Log.i("Hello","Sorted message recieved");
                        String[] op = msgs[1].split("_");
                        for(int i=0;i<op.length;i++){
                            String[] hn = op[i].split("@");
                            String h = hn[0];
                            String p = hn[1];
                            if(! online_ports.contains(h)){
                                Log.i("Hello not in list",h);
                                online_ports.add(h);
                                hash_node_map.put(h,p);
                            }
                        }
                        Collections.sort(online_ports);
                        calcPredSucc();
                        Log.i("Hello", "Pred: " + PREDECESSOR + " Succ: " + SUCCESSOR);
                        Log.i("Hey hash map", String.valueOf(hash_node_map));
                    }
                    if(msgs[0].equals("INSERT")){
                        Log.i("insert","recieved at server");
                        String key_val[] = msgs[1].split("_");
                        ContentValues contentValues = new ContentValues();
                        contentValues.put("key",key_val[0]);
                        contentValues.put("value",key_val[1]);
                        Log.i("insert","recieved key: "+key_val[0] + "recieved val: "+key_val[1]);
                        Uri mUri = buildUri("content", "edu.buffalo.cse.cse486586.simpledht.provider");
                        insert(mUri,contentValues);
                    }
                    if(msgs[0].equals("QUERY")) {
                        if (msgs[1].equals("*")) {
                            String key_val = "";
                            for (String key : data.keySet()) {
                                String val = data.get(key);
                                key_val = key_val + key + "@" + val + "_";
                            }

                            if(msgs[2].equals(hash_node_map.get(SUCCESSOR))){
                                //key_val = key_val.substring(0,key_val.length()-1);
                                String msgToSend = "";
                                if(msgs.length == 3){
                                    msgToSend = "VAL * " + key_val;
                                }else {
                                    msgToSend = "VAL * " + msgs[3] + key_val;
                                }
                                String port_num = hash_node_map.get(SUCCESSOR);
                                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(port_num));
                                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                                out.writeObject(msgToSend);
                                out.close();
                                socket.close();
                            }
                            else {
                                String msgToSend = msg + key_val;
                                String port_num = hash_node_map.get(SUCCESSOR);
                                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(port_num));
                                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                                out.writeObject(msgToSend);
                                out.close();
                                socket.close();
                            }
                        } else {
                            Log.i("query", "recieved at server");
                            String key_sourcePort[] = msgs[1].split("_");
                            Log.i("query", "recieved key is: " + key_sourcePort[0]);
                            String val = data.get(key_sourcePort[0]);
                            Log.i("query", "key is: " + key_sourcePort[0] + "value is: " + val);
                            if (val == null) {
                                Log.i("query", "value not found at current node sending to succ " + SUCCESSOR);
                                String port_num = hash_node_map.get(SUCCESSOR);
                                Log.i("query", port_num);
                                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(port_num));
                                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                                out.writeObject(msg);
                                out.close();
                                socket.close();

                            } else {
                                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                        Integer.parseInt(key_sourcePort[1]));
                                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                                String val_m = "VAL " + val;
                                out.writeObject(val_m);
                                Log.i("query", "value found at current node returning to " + key_sourcePort[1]);
                                out.close();
                                socket.close();
                            }
                        }
                    }
                    if(msgs[0].equals("VAL")){
                        if(msgs[1].equals("*")){
                            if(msgs.length == 3) {
                                Log.i("query","there is some data from the nodes");
                                star_text = msgs[2];
                            }
                            star_res = true;
                        }
                        else {
                            Log.i("query", "eureka value found");
                            recieved_val = msgs[1];
                        }
                    }
                    if(msgs[0].equals("DELETE")){
                        if(msgs[1].equals("*")){}
                        String val = data.remove(msgs[1]);
                        if(val == null){
                            if(! msgs[2].equals(hash_node_map.get(SUCCESSOR))) {
                                Log.i("delete", "value not found at current node sending to succ " + SUCCESSOR);
                                String port_num = hash_node_map.get(SUCCESSOR);
                                Log.i("delete", port_num);
                                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(port_num));
                                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                                out.writeObject(msg);
                                out.close();
                                socket.close();
                            }
                        }
                    }
                    s.close();
                }
            }catch (IOException e){ e.printStackTrace(); } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
            return null;
        }

        protected void onProgressUpdate(String...strings) {
            /*
             * The following code displays what is received in doInBackground().
             */
            return;
        }
    }

    private class ClientTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... msgs) {

            String msgToSend = msgs[0];
            String[] flag_msg = msgToSend.split(" ");
            Log.i("Hello send message is: ",msgToSend);

            byte[] b = new byte[] {10, 0, 2, 2};

            try {
                if(flag_msg[0].equals("join")) {
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(AVD0_PORT));
                    ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                    out.writeObject(msgToSend);
                    Log.i("Hello", "join message sent");
                    out.close();
                    socket.close();
                }
                else if(flag_msg[0].equals("INSERT")){
                    Log.i("insert","sending insert message to succ");
                    Log.i("insert",SUCCESSOR);
                    String port_num = hash_node_map.get(SUCCESSOR);
                    Log.i("insert",port_num);
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(port_num));
                    ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                    out.writeObject(msgToSend);
                    Log.i("insert","INSERT message sent to "+port_num);
                    out.close();
                    socket.close();
                }
                else if(flag_msg[0].equals("QUERY")){
                    Log.i("query","sending query to succ");
                    Log.i("query",SUCCESSOR);
                    String port_num = hash_node_map.get(SUCCESSOR);
                    Log.i("query",port_num);
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(port_num));
                    ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                    out.writeObject(msgToSend);
                    Log.i("query","QUERY message sent to "+port_num);
                    out.close();
                    socket.close();
                }
                else if(flag_msg[0].equals("DELETE")){
                    Log.i("delete","sending delete to succ");
                    Log.i("delete",SUCCESSOR);
                    String port_num = hash_node_map.get(SUCCESSOR);
                    Log.i("delete",port_num);
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(port_num));
                    ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                    out.writeObject(msgToSend);
                    Log.i("delete","DELETE message sent to "+port_num);
                    out.close();
                    socket.close();
                }

            } catch (UnknownHostException e) {
                Log.e("Hello", "ClientTask UnknownHostException");
            } catch (IOException e) {
                Log.e("Hello", "ClientTask socket IOException");
            }

            return null;
        }
    }
}
