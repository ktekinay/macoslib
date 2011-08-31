#tag Class
Class CFURL
Inherits CFType
	#tag Event
		Function ClassID() As UInt32
		  return me.ClassID
		End Function
	#tag EndEvent

	#tag Event
		Function VariantValue() As Variant
		  return me.StringValue
		End Function
	#tag EndEvent


	#tag Method, Flags = &h0
		Function AbsoluteURL() As CFURL
		  #if TargetMacOS
		    soft declare function CFURLCopyAbsoluteURL lib CarbonLib (relativeURL as Ptr) as Ptr
		    
		    if me <> nil then
		      return new CFURL(CFURLCopyAbsoluteURL(me), true)
		    else
		      return new CFURL(nil, not CFType.hasOwnership)
		    end if
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function AppendComponent(pathComponent as String, isDirectory as Boolean) As CFURL
		  //creates a new CFURL object with pathComponent appended to the path of this object.  
		  //isDirectory tells the function whether to add a trailing slash.
		  #if targetMacOS
		    declare function CFURLCreateCopyAppendingPathComponent lib CarbonLib (allocator as Ptr, url as Ptr, pathComponent as CFStringRef, isDirectory as Boolean) as Ptr
		    
		    return new CFURL(CFURLCreateCopyAppendingPathComponent(nil, self, pathComponent, isDirectory), CFType.hasOwnership)
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function ClassID() As UInt32
		  #if targetMacOS
		    declare function TypeID lib CarbonLib alias "CFURLGetTypeID" () as UInt32
		    static id as UInt32 = TypeID
		    return id
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(baseURL as CFURL, relativeURL as String)
		  #if targetMacOS
		    soft declare function CFURLCreateWithString lib CarbonLib (allocator as Ptr, URLString as CFStringRef, baseURL as Ptr) as Ptr
		    
		    if baseURL is nil then
		      super.Constructor CFURLCreateWithString(nil, relativeURL, nil), true
		    else
		      super.Constructor CFURLCreateWithString(nil, relativeURL, baseURL.Reference), true
		    end if
		  #endif
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(f as FolderItem)
		  if not (f is nil) then
		    me.Constructor f.URLPath
		  else
		    me.Constructor nil, not CFType.hasOwnership
		  end if
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(theURL as String)
		  me.Constructor nil, theURL
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function CopyHostName(url as CFURL) As CFStringRef
		  #if targetMacOS
		    soft declare function CFURLCopyHostName lib CarbonLib (anURL as Ptr) as CFStringRef
		    
		    return CFURLCopyHostName(url)
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function CopyNetLocation(url as CFURL) As CFStringRef
		  #if targetMacOS
		    soft declare function CFURLCopyNetLocation lib CarbonLib (anURL as Ptr) as CFStringRef
		    
		    return CFURLCopyNetLocation(url)
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function CopyPassword(url as CFURL) As CFStringRef
		  #if targetMacOS
		    soft declare function CFURLCopyPassword lib CarbonLib (anURL as Ptr) as CFStringRef
		    
		    return CFURLCopyPassword(url)
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function CopyQueryString(url as CFURL) As CFStringRef
		  #if targetMacOS
		    soft declare function CFURLCopyQueryString lib CarbonLib (anURL as Ptr) as CFStringRef
		    
		    return CFURLCopyQueryString(url)
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function CopyScheme(url as CFURL) As CFStringRef
		  #if targetMacOS
		    soft declare function CFURLCopyScheme lib CarbonLib (anURL as Ptr) as CFStringRef
		    
		    return CFURLCopyScheme(url)
		  #endif
		End Function
	#tag EndMethod

	#tag DelegateDeclaration, Flags = &h21
		Private Delegate Function CopyStringValueDelegate(url as CFURL) As CFStringRef
	#tag EndDelegateDeclaration

	#tag Method, Flags = &h21
		Private Shared Function CopyUserName(url as CFURL) As CFStringRef
		  #if targetMacOS
		    soft declare function CFURLCopyUserName lib CarbonLib (anURL as Ptr) as CFStringRef
		    
		    return CFURLCopyUserName(url)
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function CreateFromFilesystemPath(path as String, pathType as Integer, isDirectory as Boolean) As CFURL
		  #if targetMacOS
		    const kCFAllocatorDefault = nil
		    
		    dim p as Ptr = CoreFoundation.CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path, pathType, isDirectory)
		    return new CFURL(p, CFType.hasOwnership)
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function CreateFromHFSPath(path as String, isDirectory as Boolean) As CFURL
		  return CreateFromFilesystemPath(path, CFURL.HFSPathStyle, isDirectory)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function CreateFromPOSIXPath(path as String, isDirectory as Boolean) As CFURL
		  return CreateFromFilesystemPath(path, CFURL.POSIXPathStyle, isDirectory)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function HostName() As String
		  return me.StringValue(AddressOf CopyHostName)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function IsDecomposable() As Boolean
		  #if TargetMacOS
		    soft declare function CFURLCanBeDecomposed lib CarbonLib (anURL as Ptr) as Boolean
		    
		    if me <> nil then
		      return CFURLCanBeDecomposed(me)
		    else
		      return false
		    end if
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function NetLocation() As String
		  return me.StringValue(AddressOf CopyNetLocation)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Password() As String
		  return me.StringValue(AddressOf CopyPassword)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Path(resolveAgainstBase as Boolean = true) As String
		  #if TargetMacOS
		    if me <> nil then
		      dim buffer as new MemoryBlock(1024)
		      do
		        soft declare function CFURLGetFileSystemRepresentation lib CarbonLib (url as Ptr, resolveAgainstBase as Boolean, buffer as Ptr, maxBufLen as Integer) as Boolean
		        
		        if CFURLGetFileSystemRepresentation(me.Reference, resolveAgainstBase, buffer, buffer.Size) then
		          exit
		        else
		          buffer.Size = 2*buffer.Size
		        end if
		      loop until buffer.Size > 65536
		      return DefineEncoding(buffer.CString(0), Encodings.SystemDefault)
		      
		    else
		      return ""
		    end if
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Port() As Integer
		  #if TargetMacOS
		    soft declare function CFURLGetPortNumber lib CarbonLib (anURL as Ptr) as Integer
		    if me <> nil then
		      return CFURLGetPortNumber(me)
		    else
		      //CFURLGetPortNumber returns -1 if not port exists; a url for which this holds is http://www.apple.com/ .  We return -1 in the case of a nil object for consistency.
		      return -1
		    end if
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function QueryString(charactersToLeaveEscaped as String = "") As String
		  return me.StringValue(AddressOf CopyQueryString)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Scheme() As String
		  return me.StringValue(AddressOf CopyScheme)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function StringValue(f as CopyStringValueDelegate) As String
		  //if f  = nil, then that's a programmer error.
		  
		  #if TargetMacOS
		    if me <> nil then
		      return f.Invoke(me)
		    else
		      return ""
		    end if
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function UserName() As String
		  return me.StringValue(AddressOf CopyUserName)
		End Function
	#tag EndMethod


	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  #if TargetMacOS
			    soft declare function CFURLGetBaseURL lib CarbonLib (anURL as Ptr) as Ptr
			    
			    if not me.IsNULL then
			      dim theBaseURL as new CFURL(CFURLGetBaseURL(me.Reference), false)
			      if not theBaseURL.IsNULL then
			        return theBaseURL
			      end if
			    end if
			  #endif
			End Get
		#tag EndGetter
		BaseURL As CFURL
	#tag EndComputedProperty

	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  if not me.IsNULL then
			    return GetFolderItem(me.StringValue, FolderItem.PathTypeURL)
			  end if
			End Get
		#tag EndGetter
		Item As FolderItem
	#tag EndComputedProperty

	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  // returns only the relative part of a URL!
			  
			  #if TargetMacOS
			    soft declare function CFURLGetString lib CarbonLib (anURL as Ptr) as Ptr
			    // Caution: If this would return a CFStringRef, we'd have to Retain its value!
			    // Instead, "new CFString()" takes care of that below
			    
			    if not me.IsNULL then
			      return new CFString(CFURLGetString(me.Reference), false)
			    end if
			  #endif
			End Get
		#tag EndGetter
		RelativeURL As String
	#tag EndComputedProperty

	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  // returns the full URL (including the base)
			  
			  #if true
			    return me.AbsoluteURL().RelativeURL
			  #else
			    // this works, too, but the above one seems more proper
			    dim base as CFURL = me.BaseURL
			    if not (base is nil) and not base.IsNULL then
			      return me.BaseURL.StringValue+me.RelativeURL
			    else
			      return me.RelativeURL
			    end if
			  #endif
			End Get
		#tag EndGetter
		StringValue As String
	#tag EndComputedProperty


	#tag Constant, Name = HFSPathStyle, Type = Double, Dynamic = False, Default = \"1", Scope = Public
	#tag EndConstant

	#tag Constant, Name = POSIXPathStyle, Type = Double, Dynamic = False, Default = \"0", Scope = Public
	#tag EndConstant

	#tag Constant, Name = WindowsPathStyle, Type = Double, Dynamic = False, Default = \"2", Scope = Public
	#tag EndConstant


	#tag ViewBehavior
		#tag ViewProperty
			Name="Description"
			Group="Behavior"
			Type="String"
			InheritedFrom="CFType"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Index"
			Visible=true
			Group="ID"
			InitialValue="-2147483648"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Left"
			Visible=true
			Group="Position"
			InitialValue="0"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Name"
			Visible=true
			Group="ID"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="RelativeURL"
			Group="Behavior"
			Type="String"
			EditorType="MultiLineEditor"
		#tag EndViewProperty
		#tag ViewProperty
			Name="StringValue"
			Group="Behavior"
			Type="String"
			EditorType="MultiLineEditor"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Super"
			Visible=true
			Group="ID"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Top"
			Visible=true
			Group="Position"
			InitialValue="0"
			InheritedFrom="Object"
		#tag EndViewProperty
	#tag EndViewBehavior
End Class
#tag EndClass
