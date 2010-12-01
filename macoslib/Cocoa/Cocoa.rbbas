#tag Module
Protected Module Cocoa
	#tag Method, Flags = &h1
		Protected Sub Initialize()
		  #if TargetMachO
		    Declare Function NSApplicationLoad Lib CocoaLib () as Boolean
		    
		    autoreleasePool = new AutoreleaseTimer
		    
		    if not NSApplicationLoad() then
		      break // oops, what's wrong here? (Maybe this happens once RB implements Cocoa support - then we can ignore this here)
		    end
		  #endif
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function LoadFramework(frameworkName as String, searchPublicFrameworks as Boolean = true) As CFBundle
		  // Call this to make a framework known to the app, so that its classRef etc. can be looked up
		  
		  Declare Function objc_msgSend Lib CocoaLib Alias "objc_msgSend" (theReceiver as Cocoa.id, theSelector as Cocoa.SEL) as UInt32 // do not return cocoa.id here because that doesn't work on PowerPC due to bug in RB (as of 2008r5.1)
		  
		  static gResult as CFBundle
		  static gDidSearch as Boolean
		  
		  if not gDidSearch then
		    // We need to find and load the TCMPortMapper framework file.
		    
		    gDidSearch = true
		    dim f as FolderItem
		    
		    if frameworkName.Right(10) <> ".framework" then
		      frameworkName = frameworkName + ".framework"
		    end
		    
		    // A built app should include it inside its Contents/Frameworks folder
		    try
		      f = App.ExecutableFile.Parent.Parent.Child("Frameworks").Child(frameworkName)
		    catch NilObjectException
		      f = nil
		    end
		    
		    if (f = nil or not f.Exists) and DebugBuild then
		      // For debugging, we also allow it to be next to the app and project file
		      f = GetFolderItem(frameworkName)
		    end
		    
		    if (f = nil or not f.Exists) and searchPublicFrameworks then
		      // Optionally, search the public framework folders
		      dim locs as NSArray = NSSearchPathForDirectoriesInDomains (5, &hFFFF, true) // get locations of "Library" folders
		      for i as Integer = 0 to locs.Count-1
		        dim dir as FolderItem = GetFolderItemFromPOSIXPath (CFString (locs.Value(i)))
		        try
		          f = dir.Child("Frameworks").Child(frameworkName)
		        catch NilObjectException
		          f = nil
		        end
		        if f <> nil and f.Exists then
		          // found
		          exit
		        end
		        f = nil
		      next
		    end
		    
		    dim tcm as CFBundle = CFBundle.NewCFBundleFromURL (CFURL(f))
		    if tcm = nil or tcm.IsNULL or not tcm.Load() then
		      if f = nil then
		        MsgBox "Oops - could not find "+frameworkName
		      else
		        MsgBox "Oops - could not load "+f.AbsolutePath
		      end
		      return nil
		    end if
		    
		    gResult = tcm
		    
		  end
		  
		  return gResult
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function ClassRef(className as String) As id
		  #if TargetMachO
		    dim theClassRef as Integer
		    Declare Function objc_getClass Lib CocoaLib (aClassName as CString) as Integer
		    
		    theClassRef = objc_getClass(className)
		    If theClassRef = 0 then
		      Raise new CocoaUnregisteredClassException(className)
		    End if
		    Return To_id(theClassRef)
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function GetFolderItemFromPOSIXPath(absolutePath as String) As FolderItem
		  // Note: The passed path must be absolute, i.e. start from root with "/"
		  
		  #if TargetMacOS
		    declare function CFURLCopyAbsoluteURL lib CarbonLib (relativeURL as Ptr) as Ptr
		    declare function CFURLCreateWithFileSystemPath lib CarbonLib (allocator as ptr, filePath as CFStringRef, pathStyle as Integer, isDirectory as Boolean) as Ptr
		    declare function CFURLGetString lib CarbonLib (anURL as Ptr) as Ptr
		    declare sub CFRelease lib CarbonLib (cf as Ptr)
		    declare function CFRetain lib CarbonLib (cf as Ptr) as CFStringRef
		    declare sub CFShow lib CarbonLib (obj as Ptr)
		    const kCFURLPOSIXPathStyle = 0
		    
		    dim url as Ptr = CFURLCreateWithFileSystemPath(nil, absolutePath, kCFURLPOSIXPathStyle, true)
		    dim str as CFStringRef = CFRetain (CFURLGetString (url))
		    CFRelease (url)
		    dim f as FolderItem = GetFolderItem (str, FolderItem.PathTypeURL)
		    return f
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function Selector(selectorName as String) As SEL
		  #if TargetMachO
		    Declare Function sel_registerName Lib CocoaLib (theName as CString) as Integer
		    
		    dim selectorRef as Integer
		    
		    selectorRef = sel_registerName(selectorName)
		    If selectorRef = 0 then
		      Raise new CocoaUnregisteredSelectorException(selectorName)
		    End if
		    Return ToSEL(selectorRef)
		  #endif
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function ToSEL(sel as Integer) As SEL
		  dim s as SEL
		  s.value = sel
		  return s
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function To_id(id as Integer) As id
		  dim s as id
		  s.value = id
		  return s
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function NSSearchPathForDirectoriesInDomains(dir as Integer, domainMask as Integer, expandTilde as Boolean) As NSArray
		  declare function searchPaths lib CocoaLib alias "NSSearchPathForDirectoriesInDomains" (dir as Integer, domainMask as Integer, expandTilde as Boolean) as Ptr
		  
		  return new NSArray (searchPaths (dir, domainMask, expandTilde), false)
		End Function
	#tag EndMethod


	#tag Note, Name = About
		From: http://www.declaresub.com/ideclare/Cocoa/index.html
		
		This module provides what in Cocoa terms is the "Foundation"
	#tag EndNote

	#tag Note, Name = Caution using 'SEL' and 'id' in declares
		This is only important if you add new Cocoa method calls yourself:
		
		If you want to call an external function (usually via "declare"), and if that function's
		return type is a selector (SEL) or generic Cocoa object (id), be cautious not to use
		such types as the return type of the declared function. Instead, have it return a UInt32
		and then assign its value to a variable of type SEL or id using the ToSEL() or To_id()
		function (or assign directly to its ".value" member, although that's a bit unclean).
		
		If you do not obey this rule, your application may not work on PowerPC processors
		because of a bug in REALbasic (as of v2008r5.1): Returning structure types from
		declare'd functions does not work.
		
		An example where you'd want to store the result of a call in a variable such as:
		
		  dim result as id
		
		Bad:
		  declare function objc_msgSend lib CocoaLib (r as id, s as SEL) as id
		  result = objc_msgSend (r, s)
		
		Good:
		  declare function objc_msgSend lib CocoaLib (r as id, s as SEL) as UInt32
		  result = To_id (objc_msgSend (r, s))
		
	#tag EndNote


	#tag Property, Flags = &h21
		Private autoreleasePool As AutoreleaseTimer
	#tag EndProperty


	#tag Constant, Name = CocoaLib, Type = String, Dynamic = False, Default = \"Cocoa.framework", Scope = Public
	#tag EndConstant

	#tag Constant, Name = CarbonLib, Type = String, Dynamic = False, Default = \"Carbon", Scope = Public
	#tag EndConstant

	#tag Constant, Name = FoundationLib, Type = String, Dynamic = False, Default = \"Foundation.framework", Scope = Public
	#tag EndConstant


	#tag Structure, Name = id, Flags = &h1
		value as UInt32
	#tag EndStructure

	#tag Structure, Name = SEL, Flags = &h1
		value as UInt32
	#tag EndStructure


	#tag ViewBehavior
		#tag ViewProperty
			Name="Name"
			Visible=true
			Group="ID"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Index"
			Visible=true
			Group="ID"
			InitialValue="2147483648"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Super"
			Visible=true
			Group="ID"
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
			Name="Top"
			Visible=true
			Group="Position"
			InitialValue="0"
			InheritedFrom="Object"
		#tag EndViewProperty
	#tag EndViewBehavior
End Module
#tag EndModule