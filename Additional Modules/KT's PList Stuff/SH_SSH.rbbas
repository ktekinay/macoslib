#tag Class
Protected Class SH_SSH
Inherits Shell
	#tag Event
		Sub Completed()
		  dim saveState as SSHState = zState
		  zState = SSHState.Disconnected
		  
		  // Only call the event if we were disconnecting normally
		  if saveState = SSHState.Connected or saveState = SSHState.Disconnecting or saveState = SSHState.Disconnected then RaiseEvent ConnectionClosed
		  
		End Sub
	#tag EndEvent

	#tag Event
		Sub DataAvailable()
		  const kPWPrompt = "Password:"
		  
		  dim promptResponse as string
		  
		  zBuffer = zBuffer + super.ReadAll
		  dim buf as string = zBuffer
		  
		  // Make sure we're still connected
		  if not me.IsRunning then
		    zState = SSHState.Disconnected
		    zBuffer = ""
		    return
		  elseif zClearingShellBuffer then
		    zBuffer = ""
		    zClearingShellBuffer = false
		    return
		  end if
		  
		  select case zState
		  case SSHState.PreliminaryCheck
		    if buf.Right( kUsernameMarker.Len ) = kUsernameMarker then
		      me.WriteLine me.Username
		    elseif buf.Right( kPWPrompt.Len ) = kPWPrompt then
		      super.Close
		      zState = SSHState.Disconnected
		      zConfirmMessage = ""
		      zGotExpectedResponse = true
		    elseif buf.InStr( kAuthenticityMarker ) > 0 then
		      super.Close
		      zState = SSHState.Disconnected
		      zConfirmMessage = buf
		      zGotExpectedResponse = true
		    elseif buf.InStr( kIDHasChangedMarker ) > 0 then
		      super.Close
		      zState = SSHState.Disconnected
		      #if not TargetWin32
		        zSSHErrorMessage = "Connection could not be established. The remote host identification has changed. Check the ""known_hosts"" file."
		      #else
		        zConfirmMessage = buf
		        zGotExpectedResponse = true
		      #endif
		    elseif buf.Trim.Right( kConnectionRefusedMarker.Len ) = kConnectionRefusedMarker then
		      super.Close
		      zState = SSHState.Disconnected
		      zSSHErrorMessage = buf
		    elseif buf.InStr( kKeyboardInteractiveMarker ) > 0 then
		      // Do nothing
		    elseif BypassUnknownPrompts then
		      // Do nothing
		    elseif RespondToPrompt( buf, promptResponse ) then
		      me.WriteLine promptResponse
		    else
		      zSSHErrorMessage = "A prompt was not handled: " + buf
		      zState = SSHState.Disconnected
		    end if
		    zBuffer = ""
		    
		  case SSHState.Connecting // Not for Windows 
		    if buf.Right( kUsernameMarker.Len ) = kUsernameMarker then
		      me.WriteLine me.Username
		    elseif buf.Right( kPWPrompt.Len ) = kPWPrompt then
		      me.WriteLine zTempPW
		      zTempPW = "" // Don't need it anymore
		      zState = SSHState.AwaitingConfirmation
		      zGotExpectedResponse = true
		    elseif buf.InStr( kAuthenticityMarker ) > 0 then
		      me.WriteLine kAuthenticityResponse
		    elseif buf.InStr( kHostAddedMarker ) > 0 then
		      // Do nothing
		    elseif buf.InStr( kKeyboardInteractiveMarker ) > 0 then
		      // Do nothing
		    elseif BypassUnknownPrompts then
		      // Do nothing
		    elseif RespondToPrompt( buf, promptResponse ) then
		      me.WriteLine promptResponse
		    else
		      zSSHErrorMessage = "A prompt was not handled: " + buf
		      zState = SSHState.Disconnected
		    end if
		    zBuffer = ""
		    
		  case SSHState.AwaitingConfirmation
		    buf = pNormalizeEOL( buf )
		    if buf = EndOfLine.UNIX then // Nothing else there
		      zBuffer = "" // Clear the buffer and wait for more
		    elseif buf.Right( kPWPrompt.Len ) = kPWPrompt then // Didn't accept the password
		      zBuffer = ""
		      zState = SSHState.PasswordRejected
		      zSSHErrorMessage = "Password rejected."
		    elseif buf.InStr( kKeyboardInteractiveMarker ) > 0 then
		      // Do nothing
		    elseif buf.InStr( kAuthenticityMarker ) > 0 or buf.InStr( kIDHasChangedMarker ) > 0 then // Needed because windows skips the connecting step 
		      zBuffer = ""
		      me.WriteLine kAuthenticityResponse
		    elseif buf.Len > 0 then // Something there so assume we're good
		      zState = SSHState.Connected
		      RaiseEvent DataAvailable // Don't clear the buffer, let the user get it
		    end if
		    
		  case SSHState.Disconnecting
		    buf = pNormalizeEOL( buf )
		    dim bufLines() as string = buf.Split( EndOfLine.UNIX )
		    for each bufLine as string in bufLines
		      if bufLine.Left( 14 ) = "Connection to " and bufLine.Right( 8 ) = " closed." then
		        zState = SSHState.Disconnected
		        zBuffer = ""
		        exit
		      end if
		    next
		    
		  else
		    RaiseEvent DataAvailable
		    
		  end
		  
		End Sub
	#tag EndEvent


	#tag Method, Flags = &h0
		Sub Close()
		  // Diconnect will call close after it's changed the state
		  
		  if zState = SSHState.Connected then
		    
		    me.Disconnect
		    
		  else
		    
		    super.Close
		    
		  end if
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Connect(password As String, timeoutTicks As Integer = kDefaultTimeoutTicks) As Boolean
		  dim r as boolean = true // Assume we will connect
		  
		  if not me.IsRunning then
		    // It doesn't matter what state it thinks it's in
		    zState = SSHState.Disconnected
		  elseif zState = SSHState.Connected then
		    return true // Already connected
		  elseif zState = SSHState.Connecting or zState = SSHState.AwaitingConfirmation then
		    zSSHErrorMessage = "This session is already trying to connect."
		    r = false
		  elseif zState = SSHState.Disconnecting or zState = SSHState.PasswordRejected then
		    zSSHErrorMessage = "This session is in the process of disconnecting."
		    r = false
		  end if
		  
		  // Init
		  zClearingShellBuffer = false
		  zTempPW = ""
		  
		  me.Mode = 2
		  zSSHErrorMessage = ""
		  
		  // Check access to SSH
		  if r then
		    zState = SSHState.PreliminaryCheck
		    dim resp as string = SSHVersion
		    if resp.InStr( kNotFoundMarker ) > 0 then
		      zSSHErrorMessage = "The SSH command path """ + SSHCommandPath + """ is not valid."
		      r = false
		    end if
		  end if
		  
		  // Check the connection
		  dim timedOut as boolean = false
		  dim startTicks as integer
		  dim cmd as string = SSHCommandLine
		  if r then
		    pClearShellBuffer()
		    zGotExpectedResponse = false
		    me.Execute cmd
		    
		    startTicks = Ticks()
		    while zState = SSHState.PreliminaryCheck
		      if ( Ticks() - startTicks ) > timeoutTicks then
		        timedOut = true
		        exit
		      else
		        me.Poll
		      end if
		    wend
		  end if
		  
		  if r then
		    if zSSHErrorMessage <> "" then
		      r = false
		      
		    elseif timedOut then
		      zSSHErrorMessage = "The connection timed out during preliminary check."
		      r = false
		      
		    elseif not zGotExpectedResponse then
		      zSSHErrorMessage = "Did not get expected response during preliminary check."
		      r = false
		      
		    else
		      zGotExpectedResponse = false
		    end if
		  end if
		  
		  // Windows only
		  if r and zConfirmMessage.Len > 0 then // Needs authentication
		    if not ConfirmConnection( zConfirmMessage ) then
		      zSSHErrorMessage = "Authentication was not allowed."
		      r = false
		    end if
		  end if
		  
		  zConfirmMessage = ""
		  
		  // If we get here and r is still true, we can confirm if asked, so...
		  
		  // Connect
		  if r then
		    super.Close // Just to be sure
		    
		    zTempPW = password
		    cmd = SSHCommandLine
		    
		    #if not TargetWin32
		      zState = SSHState.Connecting
		    #else
		      zState = SSHState.AwaitingConfirmation
		    #endif
		    me.Execute cmd
		    
		    startTicks = Ticks()
		    while ( zState = SSHState.Connecting or zState = SSHState.AwaitingConfirmation ) and me.IsRunning
		      if ( Ticks() - startTicks ) > timeoutTicks then
		        timedOut = true
		        exit
		      else
		        me.Poll
		      end if
		    wend
		    
		    zTempPW = ""
		    
		    if zSSHErrorMessage.Len > 0 then
		      r = false
		      
		    elseif timedOut then
		      zSSHErrorMessage = "The connection timed out while trying to connect."
		      r = false
		      
		    elseif zState = SSHState.Connected then
		      r = true
		      
		    elseif me.IsRunning then
		      // Error message is filled in DataAvailable 
		      r = false
		    end if
		  end if
		  
		  // Clean up
		  if not r then
		    super.Close
		    zState = SSHState.Disconnected
		    pClearShellBuffer
		  end if
		  
		  // Make sure
		  zTempPW = ""
		  zClearingShellBuffer = false
		  return r
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Connect(connectAddress As String, connectUsername As String, connectPassword As String, timeoutTicks As Integer = kDefaultTimeoutTicks) As Boolean
		  me.Address = connectAddress.Trim
		  me.Username = connectUsername
		  
		  return me.Connect( connectPassword, timeoutTicks )
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Destructor()
		  me.Close
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Disconnect()
		  const kWaitTicks = 60
		  
		  dim buf as string = me.ReadAll // Clear the buffer
		  #pragma unused buf
		  
		  if zState = SSHState.Connected then
		    
		    zState = SSHState.Disconnecting
		    
		    // Try to disconnected normally
		    #if TargetWin32
		      me.WriteLine kLogoutCmd
		    #else
		      me.Write kLogoutCmd
		    #endif
		    
		    dim startTicks as integer = Ticks()
		    while zState = SSHState.Disconnecting and me.IsRunning and ( Ticks() - startTicks ) < kWaitTicks
		      me.Poll
		    wend
		    
		  end if
		  
		  // Regardless, force it
		  me.Close // Force it
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub pClearShellBuffer()
		  const kTimeoutTicks = 30
		  
		  if not me.IsRunning then
		    call super.ReadAll
		  else
		    zClearingShellBuffer = true
		    
		    dim startTicks as integer = Ticks
		    do
		      me.Poll // The clearing is handled in the DataAvailable event 
		    loop until ( Ticks - startTicks ) > kTimeoutTicks or not( zClearingShellBuffer )
		    
		    zClearingShellBuffer = false
		  end if
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function pNormalizeEOL(str As String) As String
		  str = str.ReplaceAll( EndOfLine.Windows, EndOfLine.UNIX )
		  str = str.ReplaceAll( EndOfLine.Macintosh, EndOfLine.UNIX )
		  
		  return str
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function pQuote(str As String) As String
		  dim r as string
		  
		  #if TargetWin32
		    r = str.ReplaceAll( """", """\""""" )
		    r = """" + r + """"
		  #else
		    r = str.ReplaceAll( "'", "'\''" )
		    r = "'" + r + "'"
		  #endif
		  
		  return r
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub pRaiseError(msg As String, code As Integer = 0)
		  dim err as new RuntimeException
		  err.Message = msg
		  err.ErrorNumber = code
		  raise err
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function ReadAll() As String
		  dim r as string = zBuffer + super.ReadAll
		  zBuffer = ""
		  
		  return r
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function SSHCommandLine() As String
		  // The command that will be issued to the shell
		  
		  dim cmd as string = SSHCommandPath
		  
		  dim sw as string = SSHSwitches.Trim
		  if sw.Len > 0  then cmd = cmd + " " + sw
		  
		  select case Protocol
		  case SSHProtocol.Any
		    // Do nothing
		  case SSHProtocol.V1Only
		    cmd = cmd + " -1"
		  case SSHProtocol.V2Only
		    cmd = cmd + " -2"
		  end select
		  
		  #if TargetWin32
		    if zTempPW.Len > 0 then
		      cmd = cmd + " -pw " + pQuote( zTempPW )
		    end if
		  #endif
		  
		  // TEMP
		  'cmd = cmd + " -tt"
		  
		  dim un as string = me.Username
		  dim ad as string = me.Address.Trim
		  
		  if ad.Len = 0 then
		    ad = "127.0.0.1" // Self
		  else
		    ad = pQuote( ad )
		  end if
		  
		  if un.Len > 0 then
		    un = pQuote( un )
		    ad = un + "@" + ad
		  end if
		  
		  cmd = cmd + " " + ad
		  return cmd
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function SSHErrorMessage() As String
		  return zSSHErrorMessage
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function SSHVersion() As String
		  dim sh as new shell
		  sh.Mode = 0
		  dim cmd as string = SSHCommandPath + " " + kVersionSwitch
		  sh.Execute cmd
		  dim vers as string = sh.Result
		  return vers
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function State() As SSHState
		  if not me.IsRunning then zState = SSHState.Disconnected // Doesn't matter what state it thought it had been in
		  return zState
		  
		End Function
	#tag EndMethod


	#tag Hook, Flags = &h0
		Event ConfirmConnection(msg As String) As Boolean
	#tag EndHook

	#tag Hook, Flags = &h0
		Event ConnectionClosed()
	#tag EndHook

	#tag Hook, Flags = &h0
		Event DataAvailable()
	#tag EndHook

	#tag Hook, Flags = &h0
		Event RespondToPrompt(prompt As String, ByRef response As String) As Boolean
	#tag EndHook


	#tag Note, Name = Legal
		This class was created by Kem Tekinay, MacTechnologies Consulting (ktekinay@mactechnologies.com).
		It is copyright ©2012, all rights reserved.
		
		You may use this class AS IS at your own risk for any purpose. The author does not warrant its use
		for any particular purpose and disavows any responsibility for bad design, poor execution,
		or any other faults.
		
		The author does not actively support this class, although comments and recommendations
		are welcome.
		
		You may modify code in this class as long as those modifications are clearly indicated
		via comments in the source code.
		
		You may distribute this class, modified or unmodified, as long as any modifications
		are clearly indicated, as noted above, and this copyright notice is not disturbed or removed.
		
		If you do make useful modifications, please let me know so I can include them in
		future versions.
	#tag EndNote

	#tag Note, Name = Usage
		This class is based on a shell and must be run in Interactive mode (mode 2).
		
		Start by calling Connect( address, username, password[, timeout] ), or set the username and address
		first, then call Connect( password[, timeout] ). The password is stored only for as long as it needs
		to respond to the SSH server.
		
		If you need additional SSH switches, you can set the SSHSwitches property first. You can see the 
		command line that will be used to connect in SSHCommandLine, and get the SSH version through
		SSHVersion.
		
		The class will handle negotiation with the server. If it gets an unknown prompt, it will raise the 
		RespondToPrompt event where you can either return true with a response or false to stop the
		connection. If you don't care about these prompts, set BypassUnknownPrompts to True.
		
		On Windows, if the fingerprint of the server has changed, you can confirm the connection, or not,
		in the ConfirmConnection event.
		
		If there is a problem during the connection, you can see the last error through SSHErrorMessage. You
		can also check the current connection state by looking at the State property.
		
		Once connected, the class will send all incoming data through the DataAvailable event. At that point,
		it's just like a normal interactive shell. Use ReadAll to get the buffer, and Write or WriteLine to 
		respond.
		
		Disconnect and Close will close the connection. Once closed by any means, you will get the 
		ConnectionClosed event.
		
	#tag EndNote


	#tag Property, Flags = &h0
		Address As String
	#tag EndProperty

	#tag Property, Flags = &h0
		#tag Note
			Set to true to ingnore any unknown prompts during connection to the server.
		#tag EndNote
		BypassUnknownPrompts As Boolean
	#tag EndProperty

	#tag Property, Flags = &h0
		Protocol As SSHProtocol = SSHProtocol.Any
	#tag EndProperty

	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  dim cmd as string = zSSHCommandPath
			  if cmd.Len = 0 then cmd = kDefaultSSHCommandPath
			  return cmd
			  
			End Get
		#tag EndGetter
		#tag Setter
			Set
			  zSSHCommandPath = value.Trim
			  
			  
			End Set
		#tag EndSetter
		SSHCommandPath As String
	#tag EndComputedProperty

	#tag Property, Flags = &h0
		SSHSwitches As String
	#tag EndProperty

	#tag Property, Flags = &h0
		Username As String
	#tag EndProperty

	#tag Property, Flags = &h21
		Private zBuffer As String
	#tag EndProperty

	#tag Property, Flags = &h21
		Private zClearingShellBuffer As Boolean
	#tag EndProperty

	#tag Property, Flags = &h21
		Private zConfirmMessage As String
	#tag EndProperty

	#tag Property, Flags = &h21
		Private zGotExpectedResponse As Boolean
	#tag EndProperty

	#tag Property, Flags = &h21
		Private zSSHCommandPath As String
	#tag EndProperty

	#tag Property, Flags = &h21
		Private zSSHErrorMessage As String
	#tag EndProperty

	#tag Property, Flags = &h21
		Private zState As SSHState = SSHState.Disconnected
	#tag EndProperty

	#tag Property, Flags = &h21
		Private zTempPW As String
	#tag EndProperty


	#tag Constant, Name = kAuthenticityMarker, Type = String, Dynamic = False, Default = \"Are you sure you want to continue connecting (yes/no)\?", Scope = Protected
		#Tag Instance, Platform = Windows, Language = Default, Definition  = \"Store key in cache\? (y/n)"
	#tag EndConstant

	#tag Constant, Name = kAuthenticityResponse, Type = String, Dynamic = False, Default = \"yes", Scope = Protected
		#Tag Instance, Platform = Windows, Language = Default, Definition  = \"y"
	#tag EndConstant

	#tag Constant, Name = kConnectionRefusedMarker, Type = String, Dynamic = False, Default = \"connection refused", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = kDefaultSSHCommandPath, Type = String, Dynamic = False, Default = \"ssh", Scope = Protected
		#Tag Instance, Platform = Windows, Language = Default, Definition  = \"plink.exe -ssh"
	#tag EndConstant

	#tag Constant, Name = kDefaultTimeoutTicks, Type = Double, Dynamic = False, Default = \"600", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = kHostAddedMarker, Type = String, Dynamic = False, Default = \"Warning: Permanently added \'", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = kIDHasChangedMarker, Type = String, Dynamic = False, Default = \"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @", Scope = Protected
		#Tag Instance, Platform = Windows, Language = Default, Definition  = \"Update cached key\? (y/n\x2C Return cancels connection)"
	#tag EndConstant

	#tag Constant, Name = kKeyboardInteractiveMarker, Type = String, Dynamic = False, Default = \"Using keyboard-interactive authentication", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = kLogoutCmd, Type = String, Dynamic = False, Default = \"~.", Scope = Protected
		#Tag Instance, Platform = Windows, Language = Default, Definition  = \"logout"
	#tag EndConstant

	#tag Constant, Name = kNotFoundMarker, Type = String, Dynamic = False, Default = \"command not found", Scope = Protected
		#Tag Instance, Platform = Windows, Language = Default, Definition  = \" is not recognized as "
	#tag EndConstant

	#tag Constant, Name = kUsernameMarker, Type = String, Dynamic = False, Default = \"User Name", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = kVersionSwitch, Type = String, Dynamic = False, Default = \"-V", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = Version, Type = Double, Dynamic = False, Default = \"1.1", Scope = Public
	#tag EndConstant


	#tag Enum, Name = SSHProtocol, Type = Integer, Flags = &h0
		Any
		  V1Only
		V2Only
	#tag EndEnum

	#tag Enum, Name = SSHState, Type = Integer, Flags = &h0
		Disconnected
		  Connecting
		  Connected
		  Disconnecting
		  AwaitingConfirmation
		  PasswordRejected
		PreliminaryCheck
	#tag EndEnum


	#tag ViewBehavior
		#tag ViewProperty
			Name="Address"
			Group="Behavior"
			Type="String"
			EditorType="MultiLineEditor"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Arguments"
			Visible=true
			EditorType="String"
			InheritedFrom="Shell"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Backend"
			Visible=true
			EditorType="String"
			InheritedFrom="Shell"
		#tag EndViewProperty
		#tag ViewProperty
			Name="BypassUnknownPrompts"
			Group="Behavior"
			Type="Boolean"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Canonical"
			Visible=true
			EditorType="Boolean"
			InheritedFrom="Shell"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Index"
			Visible=true
			Group="ID"
			Type="Integer"
			InheritedFrom="Shell"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Left"
			Visible=true
			Group="Position"
			InheritedFrom="Shell"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Mode"
			Visible=true
			EditorType="Integer"
			InheritedFrom="Shell"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Name"
			Visible=true
			Group="ID"
			InheritedFrom="Shell"
		#tag EndViewProperty
		#tag ViewProperty
			Name="SSHCommandPath"
			Group="Behavior"
			Type="String"
			EditorType="MultiLineEditor"
		#tag EndViewProperty
		#tag ViewProperty
			Name="SSHSwitches"
			Group="Behavior"
			Type="String"
			EditorType="MultiLineEditor"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Super"
			Visible=true
			Group="ID"
			InheritedFrom="Shell"
		#tag EndViewProperty
		#tag ViewProperty
			Name="TimeOut"
			Visible=true
			EditorType="Integer"
			InheritedFrom="Shell"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Top"
			Visible=true
			Group="Position"
			InheritedFrom="Shell"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Username"
			Group="Behavior"
			Type="String"
			EditorType="MultiLineEditor"
		#tag EndViewProperty
	#tag EndViewBehavior
End Class
#tag EndClass
