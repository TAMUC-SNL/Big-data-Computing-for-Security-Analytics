import java.util.*;
import java.net.*;

import org.apache.hadoop.fs.*;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.io.*;
import org.apache.hadoop.mapred.*;
import org.apache.hadoop.util.*;
import org.apache.hadoop.mapred.lib.*;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.StringTokenizer;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.IntWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.MapReduceBase;
import org.apache.hadoop.mapred.OutputCollector;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.mapred.TextInputFormat;
import org.apache.hadoop.mapred.lib.MultipleInputs;
import org.apache.hadoop.mapred.lib.MultipleOutputFormat;
import org.apache.hadoop.mapred.lib.MultipleTextOutputFormat;


/*
* SituationAnalyzer.java
*
* Version:	1.0
*		
* Author:	Ilhwan Moon	
*		Jinoh Kim	
*		ICEL (Intelligent Cyberspace Engineering Lab)
*
* This file is part of ETRI project.
*
----------------------------------------------------------
* Copyright (c) 2013-2014 SNL(System and Networks Lab)
* Department of Computer Science, Texas A&M University-Commerce
* All Right Reserved.
----------------------------------------------------------
*/



public class SituationAnalyzer {		
	static abstract class MyMultipleOutputFormat 
		extends MultipleOutputFormat<Text, Text> {
		@Override
	    protected String generateFileNameForKeyValue(Text key, Text value, String name) {
			return name;
	    }
	}
	
 public static class TokenizerMapper 
 
 extends MapReduceBase
 
 implements Mapper<Object, Text, Text, IntWritable>{
  
  private Text alert = new Text();
  public void map(Object key, Text value,
		  OutputCollector<Text, IntWritable> output, Reporter reporter) throws IOException {


    StringTokenizer itr = new StringTokenizer(value.toString(),",");
    int idx = 0;
    int tokenCount = itr.countTokens();
    String S ="", temp = "";    
    
    while (itr.hasMoreTokens() ) {
    	
    	temp = itr.nextToken();
    	    	
    	// Count of key 
    	int count = 1; 
    	
    	/* input data: 
    	 * T_0,S1-1,200.0.0.227,200.1.86.240,CVE-4844	1
    	 * */
    	 
    	String[] strCnt = temp.split("\t");
    	if(strCnt.length > 1)
    	{
    		count = Integer.parseInt(strCnt[1]);
    		temp = strCnt[0];
    	}
    	
    	IntWritable one = new IntWritable(count);
    	
    	if(idx == tokenCount-1)	// last token
    	{
    		S += temp;
    		alert.set(S);
    		output.collect(alert, one);
    	}
    	else if(idx != 0)		//	ignore first token
		{
			S += temp + ",";
		}    	    	    	   
		idx++;    	
    }   
  }
}
 
 
 static class IntSumReducer extends MapReduceBase implements Reducer<Text, IntWritable, Text, IntWritable> {
    
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
  if (otherArgs.length < 5) {
    System.err.println("Usage: EventAnalyzer <input> <output> <mapNum> <reduceNum>");
    System.exit(2);
  }
 
  JobConf jobConf = new JobConf(conf,SituationAnalyzer.class);
  
  int mapNum = Integer.parseInt(otherArgs[2]);
  int reduceNum = Integer.parseInt(otherArgs[3]);

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
  
  jobConf.setMapperClass(SituationAnalyzer.TokenizerMapper.class);
  jobConf.setCombinerClass(IntSumReducer.class);
  jobConf.setReducerClass(IntSumReducer.class);
  
  
  MultipleInputs.addInputPath(jobConf, new Path(otherArgs[0]),TextInputFormat.class, TokenizerMapper.class);

  FileOutputFormat.setOutputPath(jobConf,new Path(otherArgs[1]));	 	  
  JobClient.runJob(jobConf);
  
  }
}


