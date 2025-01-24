use std::any::type_name;
use syn::{FnArg, Path};
use syn::{Meta, Token};
use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::parse::ParseStream;
use syn::parse_quote;
use syn::{parse_macro_input, Attribute, ItemFn};
use syn::{Expr, Lit, LitStr};
use syn::token::{At, Comma};
use syn::parse::Parse;
use syn::punctuated::Punctuated;

#[proc_macro_attribute]
pub fn require_scopes(attr: TokenStream, input: TokenStream) -> TokenStream {
    let scope_list = parse_macro_input!(attr as ScopeList);
    let scopes: Vec<_> = scope_list.scopes.iter().map(|lit| lit.value()).collect();

    let jwt_claims: FnArg = parse_quote!(
        jwt_claims: Extension<Arc<JwtClaims>>
    );

    // Parse the input tokens as a function
    let mut func = parse_macro_input!(input as ItemFn);

    // Extract the function body
    let body = &func.block;

    func.sig.inputs.insert(0,jwt_claims);

    // Adds the custom logic to handle the authorization of the handler.
    func.block = syn::parse_quote!({
        let required_scopes = vec![#(#scopes),*];
        let received_scopes = jwt_claims.scopes.split(" ").collect::<Vec<_>>();
    
        if !received_scopes.iter().any(|scope| required_scopes.contains(scope)) && !received_scopes.contains(&"all") {
            let message = format!("Missing Required Scopes: {:?}, Received Scopes: {:?}", required_scopes, received_scopes);
            Err(AppErrors::Forbidden(message.to_string()))?;
        }
        #body
    });

    // Generate the modified function
    let output = quote! {
        #func
    };

    // Convert the generated code back into a TokenStream
    output.into()
}

struct ScopeList {
    scopes: Punctuated<LitStr, Token![,]>,
}

impl Parse for ScopeList {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(ScopeList { scopes: Punctuated::parse_terminated(input)? })
    }
    // fn parse(input: ParseStream) -> Result<Self> {
    //     let scopes = input.parse_terminated(LitStr::parse)?;
    //     Ok(ScopeList { scopes })
    // }
}
