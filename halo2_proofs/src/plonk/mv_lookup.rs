use super::circuit::Expression;
use ff::Field;
use std::fmt::{self, Debug};

pub(crate) mod prover;
pub(crate) mod verifier;

#[derive(Clone)]
pub struct Argument<F: Field> {
    pub(crate) name: &'static str,
    pub(crate) input_expressions: Vec<Expression<F>>,
    pub(crate) table_expressions: Vec<Expression<F>>,
}

impl<F: Field> Debug for Argument<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Argument")
            .field("input_expressions", &self.input_expressions)
            .field("table_expressions", &self.table_expressions)
            .finish()
    }
}

impl<F: Field> Argument<F> {
    /// Constructs a new lookup argument.
    ///
    /// `table_map` is a sequence of `(input, table)` tuples.
    pub fn new(name: &'static str, table_map: Vec<(Expression<F>, Expression<F>)>) -> Self {
        let (input_expressions, table_expressions) = table_map.into_iter().unzip();
        Argument {
            name,
            input_expressions,
            table_expressions,
        }
    }

    pub(crate) fn required_degree(&self) -> usize {
        assert_eq!(self.input_expressions.len(), self.table_expressions.len());

        let mut input_degree = 0;
        for expr in self.input_expressions.iter() {
            input_degree = std::cmp::max(input_degree, expr.degree());
        }
        let mut table_degree = 0;
        for expr in self.table_expressions.iter() {
            table_degree = std::cmp::max(table_degree, expr.degree());
        }

        /*
            q(X) = ((t(X) + α) * (f_i(X) + α) * (ϕ(gX) - ϕ(X)) - (t(X) + α) * (f_i + α) * (1/(f_i(X) + α) - m(X) / (t(X) + α))) mod zH(X)
                = table_degree + input_degree + 1 - 1
        */
        table_degree + input_degree
    }

    /// Returns input of this argument
    pub fn input_expressions(&self) -> &Vec<Expression<F>> {
        &self.input_expressions
    }

    /// Returns table of this argument
    pub fn table_expressions(&self) -> &Vec<Expression<F>> {
        &self.table_expressions
    }
}