use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parse;
use syn::parse::ParseStream;
use syn::parse_quote;
use syn::punctuated::Punctuated;
use syn::FnArg;
use syn::LitStr;
use syn::Token;
use syn::{parse_macro_input, ItemFn};
use syn::{GenericArgument, PathArguments, Type};

#[proc_macro_attribute]
pub fn require_scopes(attr: TokenStream, input: TokenStream) -> TokenStream {
    let scope_list = parse_macro_input!(attr as ScopeList);
    let scopes: Vec<_> = scope_list.scopes.iter().map(|lit| lit.value()).collect();

    let mut func = parse_macro_input!(input as ItemFn);
    let jwt_claims: FnArg = parse_quote!(
        jwt_claims: Extension<Arc<JwtClaims>>
    );
    // Only adds the Extension<Arc<JwtClaims>>> if it is not present on the handler
    if !is_extension_of_jwtclaims(&func) {
        func.sig.inputs.insert(0, jwt_claims);
    }
    // Gets the fn body
    let body = &func.block;

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

    // Recreate the FN
    let output = quote! {
        #func
    };

    // finally converts to TokenStream
    output.into()
}

struct ScopeList {
    scopes: Punctuated<LitStr, Token![,]>,
}

impl Parse for ScopeList {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(ScopeList {
            scopes: Punctuated::parse_terminated(input)?,
        })
    }
    // fn parse(input: ParseStream) -> Result<Self> {
    //     let scopes = input.parse_terminated(LitStr::parse)?;
    //     Ok(ScopeList { scopes })
    // }
}

fn is_extension_of_jwtclaims(func: &syn::ItemFn) -> bool {
    for input in func.sig.inputs.iter() {
        if let FnArg::Typed(pat_type) = input {
            if let Type::Path(type_path) = &*pat_type.ty {
                // Check if the outer type is `Extension`
                if let Some(first_segment) = type_path.path.segments.first() {
                    if first_segment.ident == "Extension" {
                        // Check if it has generic arguments
                        if let PathArguments::AngleBracketed(angle_brackets) =
                            &first_segment.arguments
                        {
                            // Look for the inner type `Arc<JwtClaims>`
                            if let Some(GenericArgument::Type(Type::Path(inner_type_path))) =
                                angle_brackets.args.first()
                            {
                                if let Some(inner_segment) = inner_type_path.path.segments.first() {
                                    if inner_segment.ident == "Arc" {
                                        // Check if `Arc` wraps `JwtClaims`
                                        if let PathArguments::AngleBracketed(arc_angle_brackets) =
                                            &inner_segment.arguments
                                        {
                                            if let Some(GenericArgument::Type(Type::Path(
                                                jwt_type_path,
                                            ))) = arc_angle_brackets.args.first()
                                            {
                                                if let Some(jwt_segment) =
                                                    jwt_type_path.path.segments.first()
                                                {
                                                    return jwt_segment.ident == "JwtClaims";
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    false
}
