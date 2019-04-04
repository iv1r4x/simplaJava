package com.vivz;

public class HelloWorld1{

     public static void main(String []args){
       String test = "hi my name is test";
       String testcopy = test;
       printMessage(testcopy);
       addNumbers(12,33);
     }
     
      public static void printMessage(String msg)
      {
          System.out.println(msg);
         
      }
      
      public static void addNumbers(int x, int y)
      {
        int a=x;
        int b=y;
        int z=x+y;

        System.out.println("Sum of x+y = " + z);
      }
}