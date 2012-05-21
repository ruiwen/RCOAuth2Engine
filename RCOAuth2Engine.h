//
//  RCOAuth2Engine.h
//
//  Created by Ruiwen Chua on 5/16/12.
//  Copyright (c) 2012 Ruiwen Chua. MIT Licensed.
//

#import "MKNetworkEngine.h"

typedef enum _RCOAuth2GrantType 
{
	none,
	authorization_code,
	
} RCOAuth2GrantType;

typedef enum _RCOAuth2Responsetype 
{
	token,
	code,
	
} RCOAuth2ResponseType;


typedef void (^RCOAuth2CompletionBlock)(NSError *error);

@interface RCOAuth2Engine : MKNetworkEngine
{
	RCOAuth2CompletionBlock _oAuthCompletionBlock;
	
	@private
	BOOL	_oAuthInProgress;
	NSMutableDictionary *_tokens;
	NSString *_hostname;
	NSString *_authPath;
	NSString *_tokenPath;
	NSString *_redirect;
}

@property (readonly) NSString *clientId;
@property (readonly) NSString *clientSecret;

- (RCOAuth2Engine *)initWithHostname:(NSString *)hostname
				  customHeaderFields:(NSDictionary *)headers
 				 		    clientId:(NSString *)clientId
						clientSecret:(NSString *)clientSecret
							authPath:(NSString *)authPath 
						   tokenPath:(NSString *)tokenPath
						 redirectURI:(NSString *)redirect;


- (BOOL)isAuthenticated;
- (void)authenticateWithCompletionBlock:(RCOAuth2CompletionBlock)completionBlock;
- (void)completeOAuthWithCode:(NSString *)code;
- (void)parseOAuth2Query:(NSURL *)url;
- (void)resetAuth;

@end

