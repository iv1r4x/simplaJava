package com.vivz;

public class HelloWorld1{

     public static void main(String []args){
       String test = "hi my name is test";
       String testcopy = test;
       printMessage(testcopy);
       addNumbers(12,34);
       delNumbers(35,14);
       trackVar(112,45);
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

    public static int addNumbersRet(int x, int y)
    {
        int a=x;
        int b=y;
        int z=x+y;

        return z;
    }

    public static void delNumbers(int x, int y)
    {
        int a=x;
        int b=y;
        int z=x-y;

        System.out.println("diff of x-y = " + z);
    }

    public static int delNumbersRet(int x, int y)
    {
        int a=x;
        int b=y;
        int z=x-y;

        return z;
    }

    public static void trackVar(int x, int y)
    {
        int a=x;
        int b=y;
        int z=addNumbersRet(a,b);
        int c = delNumbersRet(a,b);
        int d = z-c;
        System.out.println("trackvar:" + d);
    }
}