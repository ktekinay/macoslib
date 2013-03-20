#tag Class
Protected Class Obj_IPV4Address
	#tag Method, Flags = &h0
		Sub Constructor(ip As String = "")
		  if ip.Trim <> "" then
		    
		    me.StringValue = ip
		    
		  end if
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Convert() As String
		  return me.StringValue
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Convert(ip As String)
		  me.StringValue = ip
		  
		End Sub
	#tag EndMethod


	#tag Property, Flags = &h0
		Byte1 As Byte
	#tag EndProperty

	#tag Property, Flags = &h0
		Byte2 As Byte
	#tag EndProperty

	#tag Property, Flags = &h0
		Byte3 As Byte
	#tag EndProperty

	#tag Property, Flags = &h0
		Byte4 As Byte
	#tag EndProperty

	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  dim parts( 3 ) as string
			  parts( 0 ) = format( Byte1, "##0" )
			  parts( 1 ) = format( Byte2, "##0" )
			  parts( 2 ) = format( Byte3, "##0" )
			  parts( 3 ) = format( Byte4, "##0" )
			  
			  return join( parts, "." )
			  
			End Get
		#tag EndGetter
		#tag Setter
			Set
			  dim parts() as string = value.Split( "." )
			  Byte1 = val( parts( 0 ) )
			  Byte2 = val( parts( 1 ) )
			  Byte3 = val( parts( 2 ) )
			  Byte4 = val( parts( 3 ) )
			  
			  // If the string is incompete, this will throw an exception
			  
			End Set
		#tag EndSetter
		StringValue As String
	#tag EndComputedProperty


End Class
#tag EndClass
