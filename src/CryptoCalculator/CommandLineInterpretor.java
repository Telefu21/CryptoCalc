package CryptoCalculator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;

public class CommandLineInterpretor 
{
	private ArrayList<String> 	commandLineStr = new ArrayList<String>();
	
	public CommandLineInterpretor() 
	{
		
	}
	
	public String runCommand()
	{	
		if(commandLineStr.isEmpty() == true)
		{
			return "!!! Invalid Command !!!";
		}
		
		String cmd = "";
		
		for(int i = 0; i < commandLineStr.size(); i++)
		{
			cmd = cmd + " " + commandLineStr.get(i);
		}
			
		ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", cmd);
		
		builder.redirectErrorStream(true);
				
		Process process = null;
		
		try 
		{			
			process = builder.start();
		} 
		
		catch (IOException e1) 
		{
			e1.printStackTrace();
		}
		
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line = null;
        String retStr = "";
        
        while (true) 
        {
            try 
            {
				line = reader.readLine();
			} 
            catch (IOException e) 
            {
				e.printStackTrace();
			}
            
            if (line == null) 
            { 
            	break; 
            }
            
            retStr = retStr + line + "\n";
        }
        
        return retStr;
	}
	
	public String runAndConfirmCommand()
	{		
		String cmd = "";
		
		for(int i = 0; i < commandLineStr.size(); i++)
		{
			cmd = cmd + " " + commandLineStr.get(i);
		}
			
		ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", cmd);
		
		builder.redirectErrorStream(true);
				
		Process process = null;
		
		try 
		{			
			process = builder.start();
		} 
		
		catch (IOException e1) 
		{
			e1.printStackTrace();
		}
		
		PrintWriter writer=new PrintWriter(process.getOutputStream());

		writer.write("y\n");
		writer.flush();
		
		writer.write("y\n");
		writer.flush();
		
		writer.close();
	     
	    return "";
	}

	public ArrayList<String> getCommandLineStr() 
	{
		return commandLineStr;
	}

	public String getEntireCommandLineStr() 
	{
		String cmd = "";
		
		for(int i = 0; i < commandLineStr.size(); i++)
		{
			cmd = cmd + " " + commandLineStr.get(i);
		}
		
		return cmd;
	}

	public void addCommandLineStr(String command) 
	{
		commandLineStr.add(command);
	}
	
	public void clearCommandLineStr() 
	{
		commandLineStr.clear();
	}
}
