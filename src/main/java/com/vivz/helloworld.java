package com.vivz;

public class HelloWorld{

     public static void main(String []args){
       String test = "hi my name is test and i want to be cool";
       String testcopy = test;
       printMessage(testcopy);
     }
     
      public static void printMessage(String msg)
      {
          System.out.println(msg);
         
      }
}