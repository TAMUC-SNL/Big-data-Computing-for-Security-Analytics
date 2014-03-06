import java.util.*;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.mapred.*;
import org.apache.hadoop.util.*;

import java.io.IOException;
import java.util.StringTokenizer;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.IntWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.MapReduceBase;
import org.apache.hadoop.mapred.OutputCollector;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.mapred.lib.MultipleInputs;

/*
* UnitAggregator.java
*
* Version:	1.0
*		
* Author:	Ilhwan Moon	
*			Jinoh Kim	
*			ICEL (Intelligent Cyberspace Engineering Lab)
*
* This file is part of ETRI project.
*
----------------------------------------------------------
* Copyright (c) 2013-2014 SNL(System and Networks Lab)
* Department of Computer Science, Texas A&M-Commerce
* All Right Reserved.
----------------------------------------------------------
*/

public class UnitAggregator {
	
	public static String getClassBasedNetworkAddress(String ipAddr) {
        String[] digits = new String[4];
        StringTokenizer st = new StringTokenizer(ipAddr, ".");

        int i=0;
        while (st.hasMoreTokens()) {
            digits[i++] = st.nextToken();
        }

        if (Integer.parseInt(digits[0]) < 128) {
            return digits[0] + ".0.0.0";
        }
        if (Integer.parseInt(digits[0]) < 192) {
            return digits[0] + "." + digits[1] + ".0.0";
        }
        return digits[0] + "." + digits[1] + "." + digits[2] + ".0";
    }
			
	public static class UnitMapper extends MapReduceBase 
		implements Mapper<Object, Text, Text, IntWritable>{
  
	private final static IntWritable one = new IntWritable(1);
	private Text alert = new Text();
	      
	public void map(Object key, Text value,
		OutputCollector<Text, IntWritable> output, Reporter reporter) throws IOException {
	
	int Time = -1;
	int idx = 0;
		
	// Situation
	String 	
		S1_1="", S1_2="", S1_3="", S1_4="", 
		S2_1="", S2_2="", S2_3="", S2_4="", S2_5="",
		S3_1="", S3_2="", S3_3="", S3_4="", S3_5="";
		
	// S: Source T: Target C: Class
	String S="", T="", C = "";
	
	// Network address source
	String Ns = "";
	
	// Network address target
	String Nt = "";
	
	String token;
	
	StringTokenizer itr = new StringTokenizer(value.toString(),",");
	
	/* 
	 * Input data samples
	 * 
	 * Second,  Source,      Target,	  Alert
	 * 0.000118,200.0.141.26,200.1.33.137,CVE-0051
	 * 0.000136,200.0.64.103,200.1.201.4,CVE-0084
	 * 0.000172,200.0.80.154,200.1.2.206,CVE-0023
	 * 
	*/
	
    while (itr.hasMoreTokens() ) {
    	
    	token = itr.nextToken();    
    	// Second
    	if(idx==0)
    	{    		
    		Time = (int) Double.parseDouble(token)/1;     	    		
    		String second = "T_" + String.valueOf(Time);
    		  	        		
    		S1_1 = second + "," + "S1-1,";
    		S1_2 = second + "," + "S1-2,";
    		S1_3 = second + "," + "S1-3,";
    		S1_4 = second + "," + "S1-4,";
    		
    		S2_1 = second + "," + "S2-1,";
    		S2_2 = second + "," + "S2-2,";
    		S2_3 = second + "," + "S2-3,";
    		S2_4 = second + "," + "S2-4,";
    		S2_5 = second + "," + "S2-5,";
    		
    		S3_1 = second + "," + "S3-1,";
    		S3_2 = second + "," + "S3-2,";
    		S3_3 = second + "," + "S3-3,";
    		S3_4 = second + "," + "S3-4,";
    		S3_5 = second + "," + "S3-5,";
    		
    	}
    	
    	// Source
    	if(idx==1)
    	{
    		S = token;
    		Ns = getClassBasedNetworkAddress(S);
    		
    		S1_1 += S + ",";
    		S1_3 += S + ",";
    		S2_1 += S + ",";    		    		
    		S2_3 += S + ","; 
    		S2_5 += S + ",";
    		S3_1 += S;
    		
    		alert.set(S3_1);
    		output.collect(alert, one);
    		
    	}
    	// Target
    	if(idx==2)
    	{
    		T = token;
    		Nt = getClassBasedNetworkAddress(T);
    		
    		S1_1 += T + ",";
    		S1_2 += T + ",";
    		S2_1 += T;
    		S2_2 += T + ",";
    		S2_4 += T + ",";
    		S3_2 += T;
    		
    		
    		alert.set(S2_1);
    		output.collect(alert, one);
    
    	    alert.set(S3_2);
    	    output.collect(alert, one);
  
    	    
    	}
    	// Alert
    	if(idx==3)
    	{    		    	
    		C = token;
    		
    		S1_1 += C;
    		S1_2 += Ns + "," + C;
    		S1_3 += Nt + "," + C;
    		S1_4 += Ns + "," + Nt + "," + C;
    		S2_2 += C;
    		S2_3 += C;
    		S2_4 += Ns;
    		S2_5 += Nt;    		
    		S3_3 += C;
    		S3_4 += Ns;
    		S3_5 += Nt;
    				  
    		alert.set(S1_1); 
    		output.collect(alert, one);
    		
    		alert.set(S1_2); 
    		output.collect(alert, one);
    		
    		alert.set(S1_3); 
    		output.collect(alert, one);
    		
    		alert.set(S1_4); 
    		output.collect(alert, one);
    		
    		alert.set(S2_2);  
    		output.collect(alert, one);

    	    alert.set(S2_3);    	
    	    output.collect(alert, one);
    	    
    	    alert.set(S2_4); 
    		output.collect(alert, one);
    		
    		alert.set(S2_5); 
    		output.collect(alert, one);
    
    	    alert.set(S3_3);   
    	    output.collect(alert, one);
    	    
    	    alert.set(S3_4); 
    		output.collect(alert, one);
    		
    		alert.set(S3_5); 
    		output.collect(alert, one);
    		    	
    	    idx = 0;
    	}
    	else
    	{
    		idx++;
    	}
	}        
  }
}


 static class IntSumReducer extends MapReduceBase 
 implements Reducer<Text, IntWritable, Text, IntWritable> {
   	 
	 private IntWritable result = new IntWritable();	 
	 public void reduce(Text key, Iterator<IntWritable> values,OutputCollector<Text, IntWritable> output,
			 Reporter reporter) throws IOException {
		 
		 	 int sum = 0;
             while (values.hasNext()) {            	 
            	sum += values.next().get();     
             }                                     
             result.set(sum);
             output.collect(key, result);
	     }
	}

 public static void main(String[] args) throws Exception {
		 
  Configuration conf = new Configuration();  
  String[] otherArgs = new GenericOptionsParser(conf, args).getRemainingArgs();
  if (otherArgs.length < 4) {
    System.err.println("Usage: UnitAggregator <input> <output> <mapNumber: Default:-1> <reduceNumber: Default:-1>");
    System.exit(2);
  }
  
  int mapNum = Integer.parseInt(otherArgs[2]);
  int reduceNum = Integer.parseInt(otherArgs[3]);
  
  JobConf jobConf = new JobConf(conf,UnitAggregator.class);
      
  if(reduceNum >= 0)
  {
	  jobConf.setNumReduceTasks(reduceNum);
  }
  
  if(mapNum >= 0)
  {
	  jobConf.setNumMapTasks(mapNum);
  }
  
  jobConf.setMapOutputKeyClass(Text.class);
  jobConf.setMapOutputValueClass(IntWritable.class);
  jobConf.setOutputKeyClass(Text.class);
  jobConf.setOutputValueClass(IntWritable.class);
  jobConf.setMapperClass(UnitAggregator.UnitMapper.class);
  jobConf.setCombinerClass(IntSumReducer.class);
  jobConf.setReducerClass(IntSumReducer.class);

  MultipleInputs.addInputPath(jobConf, new Path(otherArgs[0]),TextInputFormat.class, UnitMapper.class);
  FileOutputFormat.setOutputPath(jobConf,new Path(otherArgs[1]));
  JobClient.runJob(jobConf);
 
 }

}

