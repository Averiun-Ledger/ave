use ave_common::{SchemaType, schematype::ReservedWords};
use std::collections::BTreeSet;

pub fn validate_fact_viewpoints(
    fact_viewpoints: &BTreeSet<String>,
    schema_id: &SchemaType,
    schema_viewpoints: Option<&BTreeSet<String>>,
) -> Result<(), String> {
    if schema_id.is_gov() {
        if !fact_viewpoints.is_empty() {
            return Err(
                "governance fact events cannot define viewpoints".to_owned()
            );
        }

        return Ok(());
    }

    let Some(schema_viewpoints) = schema_viewpoints else {
        return Err(
            "tracker fact evaluation is missing schema viewpoints".to_owned()
        );
    };

    if schema_viewpoints.is_empty() && !fact_viewpoints.is_empty() {
        return Err(format!("schema {} does not define viewpoints", schema_id));
    }

    for viewpoint in fact_viewpoints {
        if viewpoint.trim().len() != viewpoint.len() {
            return Err("viewpoints cannot have surrounding whitespace".to_owned());
        }

        if viewpoint.is_empty() {
            return Err("viewpoints cannot be empty".to_owned());
        }

        if viewpoint == &ReservedWords::AllViewpoints.to_string() {
            return Err(
                "AllViewpoints is not valid in fact requests; use an empty viewpoints set to indicate an unsegmented event"
                    .to_owned(),
            );
        }

        if viewpoint.len() > 100 {
            return Err(
                "viewpoints cannot be longer than 100 characters".to_owned()
            );
        }
    }

    if fact_viewpoints.is_empty() {
        return Ok(());
    }

    for viewpoint in fact_viewpoints {
        if !schema_viewpoints.contains(viewpoint) {
            return Err(format!(
                "viewpoint '{}' is not defined in schema {}",
                viewpoint, schema_id
            ));
        }
    }

    Ok(())
}
