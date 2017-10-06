/*
	@author ben krig
	9/27/17
	
	TODO:
		comment all methods

		security, contract owner address, self destruct, etc.
			implement a contract "pause" feature usable only by address:owner for security
			implement security checks like hashed passwords and access ids to access public methods in contract

		finding metadata for block nodes

		queryPerson
			return correct output for null.
*/
pragma solidity ^0.4.4;
import "../installed_contracts/jsmnsol-lib/contracts/JsmnSolLib.sol";
import "../installed_contracts/solidity-stringutils/strings.sol";

contract KYC {
	using strings for *;

	struct Person {
		bytes id;
		InfoElement[] infoElements;
	}

	struct InfoElement {
		string comments;
		string elementType;
		string elementValue;
		string hash;
		string id;
		string simulationId;
		string status;
		string title;
		string validTill;
		string verificationProof;
		string verifiedOn;
	}

	struct SubmittedRequest {
		bytes id;
		string version;
		string submittedOn;
		Person person;
	}

	address owner;
	mapping (bytes => Person) persons;
	mapping (bytes => SubmittedRequest) submittedRequests;

	/*
		Constructor
	*/
	function KYC() {
		owner = msg.sender;
	}
	/*
	----------------------------------------------------------------------------------

	EXTERNAL

	----------------------------------------------------------------------------------
	*/
	/*
		External createPerson
		@description
			Creates a new Person from a given ID.
		@params
			_id (bytes) : ID with which to create a new Person.
		@return
			(void)
	*/
	function createPerson(bytes _id) external {
		persons[_id].id = _id;
	}
	/*
		External queryPerson
		@description
			Searches persons mapping for a specific Person with a given ID.
		@params:
			_id (bytes) : ID of Person we are searching for
		@return:
			(bytes) - The ID of the person we are searching for
			(string) - JSONArray as a String of all InfoElements within Person
	*/
	function queryPerson(bytes _id) external returns (bytes, string) {
		if(sha3(persons[_id].id) == sha3(_id)) {
			return (persons[_id].id, getInfoElements(_id));
		}

		return ("_id", "[ ]");
	}
	/*
		External deletePerson
		@description:
			Deletes Person with given ID from persons mapping.
		@params:
			_id (bytes) : ID of Person we are deleting.
		@return:
			(void)
	*/
	function deletePerson(bytes _id) external {
		delete persons[_id];
	}
	/*
		External updateInfoElement
		@description: 
			Searches for an InfoElement belonging to _personid that has _elementid. 
			If InfoElement with same ID is found, overwrites the info element, otherwise a new element is pushed into infoElements[]
		
		@params: 
			_personid (bytes) : ID of the Person we are searching for
			_json (string) : _json is a STRINGIFIED JSON Object of an InfoElement e.g { "key" : "value" } -- NOT { key : "value" }
		@return:
			(void)
	*/
	function updateInfoElement(bytes _personid, string _json) external {
		bool found = false;
		uint index = 0;
		uint length = persons[_personid].infoElements.length;
		InfoElement memory newInfoElement = parseInfoElement(_json);

		for(index; index < length; index ++) {
			if( sha3(persons[_personid].infoElements[index].id) == sha3(newInfoElement.id) ) {
				found = true;
				break;
			}
		}
		if(found) {
			persons[_personid].infoElements[index] = newInfoElement;
		}
		else {
			persons[_personid].id = _personid;
			persons[_personid].infoElements.push(newInfoElement);
		}
	}
	/*
		External queryInfoElement
		@description: 
			Determines if a specific person has a single, specific element, returns the value in a JSON String
		@params:
			_personid (bytes) : ID of the Person we are searching within.
			_elementid (string) : InfoElement.id of the InfoElement we are searching for within the Person struct.
		@return:
			(string) : If _elementid is found, returns an InfoElement in JSON Format
				If _elementid is NOT found, returns an empty JSON Object. " { } "
	*/
	function queryInfoElement(bytes _personid, string _elementid) external returns (string) {
		bool found = false;
		uint index = 0;
		uint length = persons[_personid].infoElements.length;

		for(index; index < length; index ++) {
			if( sha3(persons[_personid].infoElements[index].id) == sha3(_elementid) ) {
				found = true;		
				break;
			}
		}
		if(found) {
			return ( stringifyInfoElement(_personid, index) );
		}
		else {
			return ( '{comments: "null",elementType: "null",elementValue: "null", hash: "null", id: "null", simulationId: "0", status: "null", title: "null", validTill: "null", verificationProof: "null", verifiedOn: "null"}' );
		}
	}
	/*
		External deleteInfoElements
		@description:
			Deletes an InfoElement with a specific ID within a specific Person.
				If _elementid IS FOUND, deletes the specific InfoElement and resizes array appropriately.
				if _elementid NOT FOUND, does nothing.
		@params:
			_personid (bytes) : ID of the Person we are searching within.
			_elementid (string) : ID of the InfoElement we would like to delete.
		@return:
			(void)
	*/
	function deleteInfoElement(bytes _personid, string _elementid) external {
		bool found = false;
		uint index = 0;
		uint length = persons[_personid].infoElements.length;

		for(index; index < length; index ++) {
			if( sha3(persons[_personid].infoElements[index].id) == sha3(_elementid) ) {
				found = true;
				break;
			}
		}
		if(found) {
			if(index >= length) {
				return;
			}
						
			for (index; index < length - 1; index ++) {
				persons[_personid].infoElements[index] = persons[_personid].infoElements[index + 1]; 
			}
			delete persons[_personid].infoElements[length - 1];
			persons[_personid].infoElements.length --;
		}
	}
	/*
		External queryRequestState
		@description
			Returns a specified SubmittedRequest in (string) format.
		@params
			_requestid (bytes) : ID of the SubmittedRequest to return.
		@return
			(string) : (string) representation of the SubmittedRequest or "" if no SubmittedRequest for the _requestid was found
	*/
	function queryRequestState(bytes _requestid) external returns (string) {
		bool found = false;
		if( sha3(submittedRequests[_requestid].id) == sha3(_requestid) ) {
			found = true;
			//requeststate to string
			return (stringifySubmittedRequest(_requestid));
		}

		return ("");
	}

	function saveRequestState(bytes _requestid, bytes _personid) external {
		SubmittedRequest request = submittedRequests[_requestid];
		if( sha3(request.id) == sha3(_requestid) ) {
			//already exists
			return;
		}
		
		request.id = _requestid;
		request.version = "v1";
		request.submittedOn = "Unknown";
		request.person = persons[_personid];
	}
	/*
	----------------------------------------------------------------------------------

	PUBLIC

	----------------------------------------------------------------------------------
	*/
	/*
		Public getInfoElements
		@description: 
			Retrieves all InfoElements belonging to a specific person and returns them as an JSON Array of JSON Objects.
		@params:
			_personid (bytes) : ID of the Person we are searching within.
		@return:
			(void)
	*/
	function getInfoElements(bytes _personid) public returns (string) {
		string memory allInfoElements = '[ ';
		uint length = persons[_personid].infoElements.length;

		if(length > 0) {
			for(uint i = 0; i < length; i ++) {
				allInfoElements = allInfoElements.toSlice().concat(stringifyInfoElement(_personid, i).toSlice());

				//if end of infoElements, add ' ] ' to close array.
				if(i == (length - 1) ) {
					allInfoElements = allInfoElements.toSlice().concat(' ]'.toSlice());
				}
				//if NOT end of infoElements, add ' , ' to continue array.
				else {
					allInfoElements = allInfoElements.toSlice().concat(' , '.toSlice());
				}
			}
		}
		else {
			allInfoElements = allInfoElements.toSlice().concat(' ]'.toSlice());
		}
		return allInfoElements;
	}
	/*
	----------------------------------------------------------------------------------

	INTERNAL (Helper Functions)

	----------------------------------------------------------------------------------
	*/
	/*
		Internal stringifyInfoElement
		@description:
			Retrieves a specific Person's InfoElement at a given index in (string) JSON Format.
		@params: 
			_personid (bytes) : ID of Person we are retrieving from.
			_index (uint): Specific index of infoElements to retrieve.
		@return:
			(string) : Returns a string representation of an InfoElement as a JSON Object. 
	*/
	function stringifyInfoElement(bytes _personid, uint _index) internal returns (string) {
		string memory s = '{ comments: "';
		InfoElement infoElement = persons[_personid].infoElements[_index];
		s = s.toSlice().concat(infoElement.comments.toSlice());
		s = s.toSlice().concat('", elementType: "'.toSlice());
		s = s.toSlice().concat(infoElement.elementType.toSlice());
		s = s.toSlice().concat('", elementValue: "'.toSlice());
		s = s.toSlice().concat(infoElement.elementValue.toSlice());
		s = s.toSlice().concat('", hash: "'.toSlice());
		s = s.toSlice().concat(infoElement.hash.toSlice());
		s = s.toSlice().concat('", id: "'.toSlice());
		s = s.toSlice().concat(infoElement.id.toSlice());
		s = s.toSlice().concat('", simulationId: "'.toSlice());
		s = s.toSlice().concat(infoElement.simulationId.toSlice());
		s = s.toSlice().concat('", status: "'.toSlice());
		s = s.toSlice().concat(infoElement.status.toSlice());
		s = s.toSlice().concat('", title: "'.toSlice());
		s = s.toSlice().concat(infoElement.title.toSlice());
		s = s.toSlice().concat('", validTill: "'.toSlice());
		s = s.toSlice().concat(infoElement.validTill.toSlice());
		s = s.toSlice().concat('", verificationProof: "'.toSlice());
		s = s.toSlice().concat(infoElement.verificationProof.toSlice());
		s = s.toSlice().concat('", verifiedOn: "'.toSlice());
		s = s.toSlice().concat(infoElement.verifiedOn.toSlice());
		s = s.toSlice().concat('" }'.toSlice());

		return s;
	}

	function stringifySubmittedRequest(bytes _requestid) internal returns (string) {
		string memory s = '{ id: "';
		SubmittedRequest request = submittedRequests[_requestid];
		s = s.toSlice().concat(string(request.id).toSlice());
		s = s.toSlice().concat('", person: { id: "'.toSlice());
		s = s.toSlice().concat(string(request.person.id).toSlice());
		s = s.toSlice().concat('", infoElements: '.toSlice());
		s = s.toSlice().concat(getInfoElements(request.person.id).toSlice());
		s = s.toSlice().concat('}, submittedOn: "'.toSlice());
		s = s.toSlice().concat(request.submittedOn.toSlice());
		s = s.toSlice().concat('", version: "'.toSlice());
		s = s.toSlice().concat(request.version.toSlice());
		s = s.toSlice().concat('" }'.toSlice());

		return s;

	}

	/*
		Internal parseInfoElement
		@description:
			Takes a STRINGIFIED and JSON Formatted InfoElement, parses and returns a struct InfoElement
		@params:
			_json (string) : The STRINGIFIED and JSON Formatted InfoElement to be parsed. 
			E.g { "key" : "value" } -- NOT { key : "value" }
		@return:
			(InfoElement) : The InfoElement created from _json.
	*/
	function parseInfoElement(string _json) internal returns (InfoElement) {
		uint returnValue;
		uint actualNum;
		JsmnSolLib.Token[] memory tokens;

		(returnValue, tokens, actualNum) = JsmnSolLib.parse(_json, 23);
		
		return(InfoElement
		({
			comments: JsmnSolLib.getBytes(_json, tokens[2].start, tokens[2].end), 
			elementType: JsmnSolLib.getBytes(_json, tokens[4].start, tokens[4].end),
			elementValue: JsmnSolLib.getBytes(_json, tokens[6].start, tokens[6].end),
			hash: JsmnSolLib.getBytes(_json, tokens[8].start, tokens[8].end),
			id: JsmnSolLib.getBytes(_json, tokens[10].start, tokens[10].end), 
			simulationId: JsmnSolLib.getBytes(_json, tokens[12].start, tokens[12].end), 
			status: JsmnSolLib.getBytes(_json, tokens[14].start, tokens[14].end), 
			title: JsmnSolLib.getBytes(_json, tokens[16].start, tokens[16].end), 
			validTill: JsmnSolLib.getBytes(_json, tokens[18].start, tokens[18].end), 
			verificationProof: JsmnSolLib.getBytes(_json, tokens[20].start, tokens[20].end), 
			verifiedOn: JsmnSolLib.getBytes(_json, tokens[22].start, tokens[22].end)
		}));		
	}
}