use crate::huge::Huge;

#[derive(Clone)]
pub struct DHKey {
    pub p: Huge,
    pub g: Huge,
    pub y: Huge
}