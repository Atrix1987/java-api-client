package com.recombee.api_client;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.google.appengine.api.urlfetch.FetchOptions;
import com.google.appengine.api.urlfetch.HTTPHeader;
import com.google.appengine.api.urlfetch.HTTPMethod;
import com.google.appengine.api.urlfetch.HTTPRequest;
import com.google.appengine.api.urlfetch.HTTPResponse;
import com.google.appengine.api.urlfetch.URLFetchService;
import com.google.appengine.api.urlfetch.URLFetchServiceFactory;

import com.recombee.api_client.api_requests.Request;
import com.recombee.api_client.api_requests.Batch;
import com.recombee.api_client.exceptions.ApiException;
import com.recombee.api_client.exceptions.ApiTimeoutException;
import com.recombee.api_client.exceptions.ResponseException;
import com.recombee.api_client.util.NetworkApplicationProtocol;

/* Start of the generated code */
import com.recombee.api_client.bindings.*;
import com.recombee.api_client.api_requests.GetItemValues;
import com.recombee.api_client.api_requests.ListItems;
import com.recombee.api_client.api_requests.GetItemPropertyInfo;
import com.recombee.api_client.api_requests.ListItemProperties;
import com.recombee.api_client.api_requests.ListSeries;
import com.recombee.api_client.api_requests.ListSeriesItems;
import com.recombee.api_client.api_requests.ListGroups;
import com.recombee.api_client.api_requests.ListGroupItems;
import com.recombee.api_client.api_requests.GetUserValues;
import com.recombee.api_client.api_requests.ListUsers;
import com.recombee.api_client.api_requests.GetUserPropertyInfo;
import com.recombee.api_client.api_requests.ListUserProperties;
import com.recombee.api_client.api_requests.ListItemDetailViews;
import com.recombee.api_client.api_requests.ListUserDetailViews;
import com.recombee.api_client.api_requests.ListItemPurchases;
import com.recombee.api_client.api_requests.ListUserPurchases;
import com.recombee.api_client.api_requests.ListItemRatings;
import com.recombee.api_client.api_requests.ListUserRatings;
import com.recombee.api_client.api_requests.ListItemCartAdditions;
import com.recombee.api_client.api_requests.ListUserCartAdditions;
import com.recombee.api_client.api_requests.ListItemBookmarks;
import com.recombee.api_client.api_requests.ListUserBookmarks;
import com.recombee.api_client.api_requests.UserBasedRecommendation;
import com.recombee.api_client.api_requests.ItemBasedRecommendation;

/* End of the generated code */
/**
* Client for sending requests to Recombee and getting replies
*/
public class RecombeeClient {

	private static final Logger logger = Logger.getLogger("Recombee");
    String databaseId;
    String token;

    NetworkApplicationProtocol defaultProtocol = NetworkApplicationProtocol.HTTP;
    String baseUri = "rapi.recombee.com";
    ObjectMapper mapper;
    URLFetchService fetcher;

    final int BATCH_MAX_SIZE = 10000; //Maximal number of requests within one batch request

    public RecombeeClient(String databaseId, String token) {
    	this.fetcher = URLFetchServiceFactory.getURLFetchService();
        this.databaseId = databaseId;
        this.token = token;
        this.mapper = new ObjectMapper();
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        this.mapper.setDateFormat(df);

        if (System.getenv("RAPI_URI") != null)
            this.baseUri = System.getenv("RAPI_URI");
    }

    public NetworkApplicationProtocol getDefaultProtocol() {
        return defaultProtocol;
    }

    public void setDefaultProtocol(NetworkApplicationProtocol defaultProtocol) {
        this.defaultProtocol = defaultProtocol;
    }
    /* Start of the generated code */
    public Item[] send(ListItems request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, Item[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListItems data to Recombee", e);
         }
         return null;
    }

    public PropertyInfo send(GetItemPropertyInfo request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, PropertyInfo.class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send GetItemPropertyInfo data to Recombee", e);
         }
         return null;
    }

    public PropertyInfo[] send(ListItemProperties request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, PropertyInfo[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListItemProperties data to Recombee", e);
         }
         return null;
    }

    public Series[] send(ListSeries request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, Series[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListSeries data to Recombee", e);
         }
         return null;
    }

    public SeriesItem[] send(ListSeriesItems request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, SeriesItem[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListSeriesItems data to Recombee", e);
         }
         return null;
    }

    public Group[] send(ListGroups request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, Group[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListGroups data to Recombee", e);
         }
         return null;
    }

    public GroupItem[] send(ListGroupItems request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, GroupItem[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListGroupItems data to Recombee", e);
         }
         return null;
    }

    public User[] send(ListUsers request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, User[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListUsers data to Recombee", e);
         }
         return null;
    }

    public PropertyInfo send(GetUserPropertyInfo request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, PropertyInfo.class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send GetUserPropertyInfo data to Recombee", e);
         }
         return null;
    }

    public PropertyInfo[] send(ListUserProperties request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, PropertyInfo[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListUserProperties data to Recombee", e);
         }
         return null;
    }

    public DetailView[] send(ListItemDetailViews request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, DetailView[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListItemDetailViews data to Recombee", e);
         }
         return null;
    }

    public DetailView[] send(ListUserDetailViews request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, DetailView[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListUserDetailViews data to Recombee", e);
         }
         return null;
    }

    public Purchase[] send(ListItemPurchases request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, Purchase[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListItemPurchases data to Recombee", e);
         }
         return null;
    }

    public Purchase[] send(ListUserPurchases request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, Purchase[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListUserPurchases data to Recombee", e);
         }
         return null;
    }

    public Rating[] send(ListItemRatings request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, Rating[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListItemRatings data to Recombee", e);
         }
         return null;
    }

    public Rating[] send(ListUserRatings request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, Rating[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListUserRatings data to Recombee", e);
         }
         return null;
    }

    public CartAddition[] send(ListItemCartAdditions request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, CartAddition[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListItemCartAdditions data to Recombee", e);
         }
         return null;
    }

    public CartAddition[] send(ListUserCartAdditions request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, CartAddition[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListUserCartAdditions data to Recombee", e);
         }
         return null;
    }

    public Bookmark[] send(ListItemBookmarks request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, Bookmark[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListItemBookmarks data to Recombee", e);
         }
         return null;
    }

    public Bookmark[] send(ListUserBookmarks request) throws ApiException {
        String responseStr = sendRequest(request);
        try {
            return this.mapper.readValue(responseStr, Bookmark[].class);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send ListUserBookmarks data to Recombee", e);
         }
         return null;
    }

    /* End of the generated code */

    public BatchResponse[] send(Batch batchRequest) throws ApiException {

        if(batchRequest.getRequests().size() > this.BATCH_MAX_SIZE) {
            return sendMultipartBatchRequest(batchRequest);
        }

        String responseStr = sendRequest(batchRequest);

        try {
            Object[] responses = this.mapper.readValue(responseStr, Object[].class);
            BatchResponse[] result = new BatchResponse[responses.length];
            for(int i=0;i<responses.length;i++)
            {
                Map<String, Object> response = (Map<String, Object>) responses[i];
                int status = (Integer) response.get("code");
                Object parsedResponse = response.get("json");
                Request request = batchRequest.getRequests().get(i);

                if(status!=200 && status!=201)
                {
                    Map<String, Object> exceptionMap = (Map<String,Object>) parsedResponse;
                    parsedResponse = new ResponseException(request, status, (String)exceptionMap.get("error"));
                }
                else
                {
                    if ((request instanceof ItemBasedRecommendation) || (request instanceof UserBasedRecommendation))
                    {
                        boolean returnProperties = false;
                        if (request instanceof ItemBasedRecommendation) returnProperties = ((ItemBasedRecommendation) request).getReturnProperties();
                        if (request instanceof UserBasedRecommendation) returnProperties = ((UserBasedRecommendation) request).getReturnProperties();

                        if(returnProperties)
                        {
                            ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                            Recommendation[] ar = new Recommendation[array.size()];
                            for(int j=0;j<ar.length;j++) ar[j] = new Recommendation((String)array.get(j).get("itemId"), array.get(j));
                            parsedResponse = ar;
                        }
                        else
                        {
                            ArrayList<String> array = (ArrayList<String>) parsedResponse;
                            Recommendation[] ar = new Recommendation[array.size()];
                            for(int j=0;j<ar.length;j++) ar[j] = new Recommendation(array.get(j));
                            parsedResponse = ar;
                        }
                    }
                    /* Start of the generated code */
                    else if (request instanceof ListItems)
                    {
                        ArrayList<String> array = (ArrayList<String>) parsedResponse;
                        Item[] ar = new Item[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new Item(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof GetItemPropertyInfo)
                    {
                        Map<String, Object> obj = (Map<String, Object>) parsedResponse;
                        parsedResponse = new PropertyInfo(obj);
                    }

                    else if (request instanceof ListItemProperties)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        PropertyInfo[] ar = new PropertyInfo[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new PropertyInfo(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListSeries)
                    {
                        ArrayList<String> array = (ArrayList<String>) parsedResponse;
                        Series[] ar = new Series[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new Series(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListSeriesItems)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        SeriesItem[] ar = new SeriesItem[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new SeriesItem(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListGroups)
                    {
                        ArrayList<String> array = (ArrayList<String>) parsedResponse;
                        Group[] ar = new Group[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new Group(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListGroupItems)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        GroupItem[] ar = new GroupItem[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new GroupItem(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListUsers)
                    {
                        ArrayList<String> array = (ArrayList<String>) parsedResponse;
                        User[] ar = new User[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new User(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof GetUserPropertyInfo)
                    {
                        Map<String, Object> obj = (Map<String, Object>) parsedResponse;
                        parsedResponse = new PropertyInfo(obj);
                    }

                    else if (request instanceof ListUserProperties)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        PropertyInfo[] ar = new PropertyInfo[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new PropertyInfo(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListItemDetailViews)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        DetailView[] ar = new DetailView[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new DetailView(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListUserDetailViews)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        DetailView[] ar = new DetailView[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new DetailView(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListItemPurchases)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        Purchase[] ar = new Purchase[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new Purchase(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListUserPurchases)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        Purchase[] ar = new Purchase[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new Purchase(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListItemRatings)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        Rating[] ar = new Rating[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new Rating(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListUserRatings)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        Rating[] ar = new Rating[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new Rating(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListItemCartAdditions)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        CartAddition[] ar = new CartAddition[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new CartAddition(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListUserCartAdditions)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        CartAddition[] ar = new CartAddition[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new CartAddition(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListItemBookmarks)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        Bookmark[] ar = new Bookmark[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new Bookmark(array.get(j));
                        parsedResponse = ar;
                    }

                    else if (request instanceof ListUserBookmarks)
                    {
                        ArrayList<Map<String, Object>> array = (ArrayList<Map<String, Object>>) parsedResponse;
                        Bookmark[] ar = new Bookmark[array.size()];
                        for(int j=0;j<ar.length;j++) ar[j] = new Bookmark(array.get(j));
                        parsedResponse = ar;
                    }
                /* End of the generated code */
                }

                result[i] = new BatchResponse(status, parsedResponse);
            }
            return result;

        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send Batch data to Recombee", e);
        }
        return null;
    }



    private BatchResponse[] sendMultipartBatchRequest(Batch batchRequest) throws ApiException {

        List<List<Request>> requestChunks = getRequestsChunks(batchRequest);
        ArrayList<BatchResponse[]> responses = new ArrayList<BatchResponse[]>();

        for(List<Request> rqs: requestChunks)
            responses.add(send(new Batch(rqs)));

        return concatenateResponses(responses);
    }

    private List<List<Request>> getRequestsChunks(Batch batchRequest) {

        ArrayList<List<Request>> result = new ArrayList<List<Request>>();
        List<Request> requests = batchRequest.getRequests();
        int fullparts = requests.size() / this.BATCH_MAX_SIZE;

        for(int i=0;i<fullparts;i++)
            result.add(requests.subList(i * this.BATCH_MAX_SIZE, (i+1) * this.BATCH_MAX_SIZE));

        if(fullparts * this.BATCH_MAX_SIZE < requests.size())
            result.add(requests.subList(fullparts * this.BATCH_MAX_SIZE, requests.size()));

        return result;
    }

    private BatchResponse[] concatenateResponses(ArrayList<BatchResponse[]> responses)
    {
        int size = 0, i = 0;

        for(BatchResponse[] rsps: responses) {
            size += rsps.length;
        }

        BatchResponse[] result = new BatchResponse[size];

        for(BatchResponse[] rsps: responses) {
            for(BatchResponse rsp: rsps)
                result[i++] = rsp;
        }
        return result;
    }    /* End of the generated code */

    public Map<String, Object> send(GetItemValues request) throws ApiException {
        String responseStr = sendRequest(request);

        TypeReference<HashMap<String,Object>> typeRef 
                = new TypeReference<HashMap<String,Object>>() {};
        try {
            return this.mapper.readValue(responseStr, typeRef);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send GetItemValues data to Recombee", e);
        }
        return null;
    }


    public Map<String, Object> send(GetUserValues request) throws ApiException {
        String responseStr = sendRequest(request);

        TypeReference<HashMap<String,Object>> typeRef 
                = new TypeReference<HashMap<String,Object>>() {};
        try {
            return this.mapper.readValue(responseStr, typeRef);
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#send]Unable to send GetUserValues data to Recombee", e);
        }
        return null;
    }


    public Recommendation[] send(UserBasedRecommendation request) throws ApiException {
        return sendRecomm(request);
    }

    public Recommendation[] send(ItemBasedRecommendation request) throws ApiException {
        return sendRecomm(request);
    }

    protected Recommendation[] sendRecomm(Request request) throws ApiException {
        String responseStr = sendRequest(request);

        try {
            return this.mapper.readValue(responseStr, Recommendation[].class);
        } catch (IOException e) {
            //might have failed because it returned also the item properties
            TypeReference<HashMap<String,Object>[]> typeRef 
                    = new TypeReference<HashMap<String,Object>[]>() {};
            try {
                Map<String, Object>[] valsArray = this.mapper.readValue(responseStr, typeRef);
                Recommendation [] recomms = new Recommendation[valsArray.length];
                for(int i=0;i<valsArray.length;i++)
                    recomms[i] = new Recommendation((String)valsArray[i].get("itemId"), valsArray[i]);
                return recomms;
            } catch (IOException e2) {
            	logger.log(Level.SEVERE, "[#sendRecomm]Unable to send to Recombee", e);
            }
         }
         return null;
    }


    public String send(Request request) throws ApiException {
        return sendRequest(request);
    }

    protected String sendRequest(Request request) throws ApiException {
        String signedUri = signUrl(processRequestUri(request));
        String protocolStr = request.getEnsureHttps() ? "https" : this.defaultProtocol.name().toLowerCase();
        String uri = protocolStr + "://" + this.baseUri + "/" + signedUri;
        try {
	        HTTPRequest httpRequest = null;
	        switch (request.getHTTPMethod()) {
	            case GET:
	                httpRequest = get(uri, request);
	                break;
	            case POST:
	                httpRequest = post(uri, request);
	                break;
	            case PUT:
	                httpRequest = put(uri, request);
	                break;
	            case DELETE:
	                httpRequest = delete(uri, request);
	                break;
	        }
            HTTPResponse response = fetcher.fetch(httpRequest); 
            checkErrors(response, request);
            return new String(response.getContent(), Charset.forName("UTF-8"));
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "[#sendRequest]", e);
            throw new ApiTimeoutException(request);
        }
    }

    private String signUrl(String url) {
        url = url + (url.contains("?") ? "&" : "?") + "hmac_timestamp=" + System.currentTimeMillis() / 1000;

        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            SecretKeySpec secret = new SecretKeySpec(this.token.getBytes(), "HmacSHA1");
            mac.init(secret);
            byte[] rawHmac = mac.doFinal(url.getBytes());
            String sign = encodeHexString(rawHmac);
            return url + "&hmac_sign=" + sign;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
        	logger.log(Level.SEVERE, "[#signUrl] While generating hmacSHA1", e);
        }
        return null;
    }

    private String processRequestUri(Request request) {
        String uri = "/" + this.databaseId + request.getPath();
        uri = appendQueryParameters(uri, request);
        return uri;
    }

    private String appendQueryParameters(String uri, Request request) {
        for (Map.Entry<String, Object> pair : request.getQueryParameters().entrySet()) {
            uri += uri.contains("?") ? "&" : "?";
            uri += pair.getKey() + "=" + formatQueryParameterValue(pair.getValue());
        }
        return uri;
    }

    private String formatQueryParameterValue(Object val) {
        try {
            return URLEncoder.encode(val.toString(), "UTF-8");
        } catch (UnsupportedEncodingException e) {
        	logger.log(Level.SEVERE, "[#formatQueryParameterValue]", e);
            return null;
        }
    }

    private HTTPRequest get(String url, Request req) throws MalformedURLException {
    	return new HTTPRequest(new URL(url), HTTPMethod.GET, getFetchOptions(req));
    }

    private HTTPRequest put(String url, Request req) throws MalformedURLException {
    	return new HTTPRequest(new URL(url), HTTPMethod.PUT, getFetchOptions(req));
    }

    private HTTPRequest delete(String url, Request req) throws MalformedURLException {
    	return new HTTPRequest(new URL(url), HTTPMethod.DELETE, getFetchOptions(req));
    }

    private HTTPRequest post(String url, Request req) throws MalformedURLException {
        try {
        	HTTPRequest request = new HTTPRequest(new URL(url), HTTPMethod.DELETE, getFetchOptions(req));
        	request.setHeader(new HTTPHeader("Content-Type", "application/json"));
        	String json = this.mapper.writeValueAsString(req.getBodyParameters());
        	request.setPayload(json.getBytes(Charset.forName("UTF-8")));
            return request;
        } catch (JsonProcessingException e) {
        	logger.log(Level.SEVERE, "[#post]", e);
        }
        return null;
    }

    private void checkErrors(HTTPResponse response, Request request) throws ResponseException {
        if(response.getResponseCode() == 200 || response.getResponseCode() == 201) return;
        throw new ResponseException(request, response.getResponseCode(), new String(response.getContent()));

    }
    
    private static FetchOptions getFetchOptions(Request req){
		FetchOptions fetchOptions = FetchOptions.Builder.withDefaults();
		fetchOptions.setDeadline((double)req.getTimeout());
		return fetchOptions;
	}
    
    /**
     * Ported from commons-codec-1.9 Hex.java
     * Converts an array of bytes into an array of characters representing the hexadecimal values of each byte in order.
     * The returned array will be double the length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * @param data
     *            a byte[] to convert to Hex characters
     * @param toDigits
     *            the output alphabet
     * @return A char[] containing hexadecimal characters
     * @since 1.4
     */
    private static String encodeHexString(final byte[] data) {
        final int l = data.length;
        final char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = DIGITS_LOWER[(0xF0 & data[i]) >>> 4];
            out[j++] = DIGITS_LOWER[0x0F & data[i]];
        }
        return new String(out);
    }
    
    private static final char[] DIGITS_LOWER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
}