use crate::util::ident_to_litstr;
use proc_macro2::TokenStream;
use quote::quote;
use syn::ItemFn;

pub(crate) fn route_impl(method: &str, path: &str, original_function: &ItemFn) -> syn::Result<TokenStream> {
    let func_name = &original_function.sig.ident;
    let vis = &original_function.vis;
    let route_name = ident_to_litstr(func_name);

    let register_describer_symbol = format!("__preinit__20_register_route_describer_{}", route_name.value());

    // Route-procedures are registered as procedures with HTTP metadata.
    // The generated shim:
    // 1. Decodes HttpRequest from raw arg bytes (wire format)
    // 2. Calls the user function with (&mut ProcedureContext, HttpRequest)
    // 3. Encodes the response via IntoRouteResponse
    // 4. Returns encoded bytes
    Ok(quote! {
        const _: () = {
            #[unsafe(export_name = #register_describer_symbol)]
            pub extern "C" fn __register_describer() {
                spacetimedb::rt::register_route_procedure::<#func_name>(#method, #path)
            }
        };

        #[allow(non_camel_case_types)]
        #vis struct #func_name { _never: ::core::convert::Infallible }

        impl #func_name {
            fn invoke(__ctx: &mut spacetimedb::ProcedureContext, __args: &[u8]) -> spacetimedb::ProcedureResult {
                spacetimedb::rt::invoke_route_procedure(#func_name, __ctx, __args)
            }
        }

        #[automatically_derived]
        impl spacetimedb::rt::ExplicitNames for #func_name {}

        #[automatically_derived]
        impl spacetimedb::rt::FnInfo for #func_name {
            type Invoke = spacetimedb::rt::ProcedureFn;
            type FnKind = spacetimedb::rt::FnKindProcedure<()>;

            const NAME: &'static str = #route_name;
            const ARG_NAMES: &'static [Option<&'static str>] = &[];
            const INVOKE: spacetimedb::rt::ProcedureFn = #func_name::invoke;
        }
    })
}
