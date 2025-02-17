// Copyright (c) 2023 ProTom
// Distributed under the MIT software license

//! NIP15
//!
//! <https:///github.com/nostr-protocol/nips/blob/master/15.md>

use alloc::string::String;
use alloc::vec::Vec;

use bitcoin::secp256k1::XOnlyPublicKey;

use crate::Tag;

/// Payload for creating or updating stall
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallData {
    /// UUID of the stall generated by merchant
    pub id: String,
    /// Stall name
    pub name: String,
    /// Stall description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Currency used
    pub currency: String,
    /// Available shipping methods
    pub shipping: Vec<ShippingMethod>,
}

impl StallData {
    /// Create a new stall
    pub fn new(id: &str, name: &str, currency: &str) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            currency: currency.into(),
            shipping: Vec::new(),
        }
    }

    /// Set the description of the stall
    pub fn description(self, description: &str) -> Self {
        Self {
            description: Some(description.into()),
            ..self
        }
    }

    /// Add a shipping method to the stall
    pub fn shipping(self, shipping: Vec<ShippingMethod>) -> Self {
        Self { shipping, ..self }
    }
}

impl From<StallData> for Vec<Tag> {
    fn from(value: StallData) -> Self {
        vec![Tag::Identifier(value.id)]
    }
}

impl From<StallData> for String {
    fn from(value: StallData) -> Self {
        serde_json::to_string(&value).unwrap_or_default()
    }
}

/// Payload for creating or updating product
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductData {
    /// UUID of the product generated by merchant
    pub id: String,
    /// Id of the stall that this product belongs to
    pub stall_id: String,
    /// Product name
    pub name: String,
    /// Description of the product
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Image urls of the product
    #[serde(skip_serializing_if = "Option::is_none")]
    pub images: Option<Vec<String>>,
    /// Currency used
    pub currency: String,
    /// Price of the product
    pub price: f64,
    /// Available items
    pub quantity: u64,
    /// Specifications of the product
    #[serde(skip_serializing_if = "Option::is_none")]
    pub specs: Option<Vec<Vec<String>>>,
    /// Shipping method costs
    pub shipping: Vec<ShippingCost>,
    /// Categories of the product (will be added to tags)
    #[serde(skip_serializing)]
    pub categories: Option<Vec<String>>,
}

impl ProductData {
    /// Create a new product
    pub fn new(id: &str, stall_id: &str, name: &str, currency: &str) -> Self {
        Self {
            id: id.into(),
            stall_id: stall_id.into(),
            name: name.into(),
            description: None,
            images: None,
            currency: currency.into(),
            price: 0.0,
            quantity: 1,
            specs: None,
            shipping: Vec::new(),
            categories: None,
        }
    }

    /// Set the description of the product
    pub fn description(self, description: &str) -> Self {
        Self {
            description: Some(description.into()),
            ..self
        }
    }

    /// Add images to the product
    pub fn images(self, images: Vec<String>) -> Self {
        Self {
            images: Some(images),
            ..self
        }
    }

    /// Set the price of the product
    pub fn price(self, price: f64) -> Self {
        Self { price, ..self }
    }

    /// Set the available quantity of the product
    pub fn quantity(self, quantity: u64) -> Self {
        Self { quantity, ..self }
    }

    /// Set the specifications of the product (e.g. size, color, etc.). Each inner vector should
    /// only contain 2 elements, the first being the name of the spec and the second being the value
    /// of the spec.
    pub fn specs(self, specs: Vec<Vec<String>>) -> Self {
        let valid = specs.into_iter().filter(|spec| spec.len() == 2).collect();
        Self {
            specs: Some(valid),
            ..self
        }
    }

    /// Add a shipping method to the product
    pub fn shipping(self, shipping: Vec<ShippingCost>) -> Self {
        Self { shipping, ..self }
    }

    /// Add categories to the product
    pub fn categories(self, categories: Vec<String>) -> Self {
        Self {
            categories: Some(categories),
            ..self
        }
    }
}

impl From<ProductData> for Vec<Tag> {
    fn from(value: ProductData) -> Self {
        let mut tags = Vec::new();
        tags.push(Tag::Identifier(value.stall_id));
        value.categories.unwrap_or_default().iter().for_each(|cat| {
            tags.push(Tag::Hashtag(cat.into()));
        });
        tags
    }
}

impl From<ProductData> for String {
    fn from(value: ProductData) -> Self {
        serde_json::to_string(&value).unwrap_or_default()
    }
}

/// A shipping method as defined by the merchant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShippingMethod {
    /// Shipping method unique id by merchant
    pub id: String,
    /// Shipping method name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Shipping method cost (currency is the same as the stall)
    pub cost: f64,
    /// Covered regions
    pub regions: Vec<String>,
}

impl ShippingMethod {
    /// Create a new shipping method
    pub fn new(id: &str, cost: f64) -> Self {
        Self {
            id: id.into(),
            name: None,
            cost,
            regions: Vec::new(),
        }
    }

    /// Set the name of the shipping method
    pub fn name(self, name: &str) -> Self {
        Self {
            name: Some(name.into()),
            ..self
        }
    }

    /// Add a region to the shipping method
    pub fn regions(self, regions: Vec<String>) -> Self {
        Self { regions, ..self }
    }

    /// Get the product shipping cost of the shipping method
    pub fn get_shipping_cost(self) -> ShippingCost {
        ShippingCost {
            id: self.id,
            cost: self.cost,
        }
    }
}

/// Delivery cost for shipping method as defined by the merchant in the product
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShippingCost {
    /// Id of the shipping method
    pub id: String,
    /// Cost to use this shipping method
    pub cost: f64,
}

/// Payload for customer creating an order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerOrder {
    /// Unique id of the order generated by customer
    pub id: String,
    /// Message type (0 in case of customer order)
    #[serde(rename = "type")]
    pub type_: usize,
    /// Name of the customer
    name: Option<String>,
    /// Address of the customer if product is physical
    address: Option<String>,
    /// Message to the merchant
    message: Option<String>,
    /// Contact details of the customer
    contact: CustomerContact,
    /// Items ordered
    items: Vec<CustomerOrderItem>,
    /// Shipping method id
    shipping_id: String,
}

/// Payload for a merchant to create a payment request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantPaymentRequest {
    /// Unique id of the order generated by customer
    pub id: String,
    /// Message type (1 in case of merchant payment request)
    #[serde(rename = "type")]
    pub type_: usize,
    /// Available payment options
    pub payment_options: Vec<PaymentOption>,
}

/// Payload to notify a customer about the received payment and or shipping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantVerifyPayment {
    /// Unique id of the order generated by customer
    pub id: String,
    /// Type of the message (2 in case of merchant verify payment)
    #[serde(rename = "type")]
    pub type_: usize,
    /// Payment successful
    pub paid: bool,
    /// Item shipped
    pub shipped: bool,
}

/// A customers contact options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerContact {
    /// Nostr pub key of the customer (optional, as not decided yet if required)
    pub nostr: Option<XOnlyPublicKey>,
    /// Phone number of the customer
    pub phone: Option<String>,
    /// Email of the customer
    pub email: Option<String>,
}

/// An item in the order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerOrderItem {
    /// Id of the product
    pub id: String,
    /// Quantity of the product
    pub quantity: u64,
}

/// A payment option of an invoice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentOption {
    /// Name of the payment option
    #[serde(rename = "type")]
    pub type_: String,
    /// Payment link (url, ln invoice, etc.)
    pub link: String,
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::*;
    #[test]
    fn test_stall_data() {
        let stall = StallData::new("123", "Test Stall", "USD")
            .description("Test Description")
            .shipping(vec![ShippingMethod::new("123", 5.0).name("default")]);
        let tags: Vec<Tag> = stall.clone().into();
        assert_eq!(tags.len(), 1);
        assert_eq!(
            tags[0],
            Tag::Identifier("123".into()),
            "tags contains stall id"
        );

        let string: String = stall.into();
        assert_eq!(
            string,
            r#"{"id":"123","name":"Test Stall","description":"Test Description","currency":"USD","shipping":[{"id":"123","name":"default","cost":5.0,"regions":[]}]}"#
        );
    }

    #[test]
    fn test_product_data() {
        let product = ProductData::new("123", "456", "Test Product", "USD")
            .images(vec!["https://example.com/image.png".into()])
            .price(10.0)
            .quantity(10)
            .specs(vec![vec!["Size".into(), "M".into()]])
            .shipping(vec![ShippingCost {
                id: "123".into(),
                cost: 5.0,
            }])
            .categories(vec!["Test".into(), "Product".into()]);

        let tags: Vec<Tag> = product.clone().into();
        assert_eq!(tags.len(), 3);
        assert_eq!(
            tags[0],
            Tag::Identifier("456".into()),
            "tags contains stall id"
        );
        assert_eq!(
            tags[1],
            Tag::Hashtag("Test".into()),
            "tags contains category"
        );
        assert_eq!(
            tags[2],
            Tag::Hashtag("Product".into()),
            "tags contains category"
        );

        let string: String = product.into();
        assert_eq!(
            string,
            r#"{"id":"123","stall_id":"456","name":"Test Product","images":["https://example.com/image.png"],"currency":"USD","price":10.0,"quantity":10,"specs":[["Size","M"]],"shipping":[{"id":"123","cost":5.0}]}"#
        );
    }
}
