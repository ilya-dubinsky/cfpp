package org.ilyadubinsky.cfpp.jose;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class JWKList extends BaseJOSEObject implements List<JWK> {
	
	private static final String JWK_KEYS = "keys";

	/* wrap the list and delegate its methods */
	@lombok.experimental.Delegate
	private ArrayList<JWK> list;
	
	private ArrayList<Map<String, Object>> contentsList;
	
	
	public JWKList() {
		list = new ArrayList<JWK>();
		contentsList = new ArrayList<>();
	}

	@Override
	protected void prepareSerialize() {
		for (JWK k : list)
			contentsList.add(k.getContents());
		
		contents.put(JWK_KEYS, contentsList);
		
		super.prepareSerialize();
	}
	
	

}
