use super::circuit::Expression;
use ff::Field;
use std::fmt::{self, Debug};

pub(crate) mod hybrid_prover;
pub(crate) mod prover;
pub(crate) mod verifier;

/*
   map (table_vec_expressions, [input_expressions])

   lookup_arguments: [(table_vec_expressions, [input_expressions)]

   // iter this map:
   {
       table_vec_expressions, vec<vec<input_expressions>>

       // compute degree, if it's bigger than some bound
           -> crete new lookup_argument: table_vec_expressions, empty
   }
*/

#[derive(Clone)]
pub struct HybridArgument<F: Field> {
    pub(crate) table_expressions: Vec<Expression<F>>,
    pub(crate) inputs_expressions: Vec<Vec<Expression<F>>>,
}

impl<F: Field> Debug for HybridArgument<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Argument")
            .field("table_expressions", &self.table_expressions)
            .field("inputs_expressions", &self.inputs_expressions)
            .finish()
    }
}

impl<F: Field> HybridArgument<F> {
    /// Constructs a new lookup argument.
    pub fn new(table: &Vec<Expression<F>>, input: &Vec<Vec<Expression<F>>>) -> Self {
        Self {
            table_expressions: table.clone(),
            inputs_expressions: input.clone(),
        }
    }

    pub(crate) fn required_degree(&self) -> usize {
        assert!(self
            .inputs_expressions
            .iter()
            .all(|input| input.len() == self.table_expressions.len()));

        let expr_degree = |input_expressions: &Vec<Expression<F>>| {
            let mut input_degree = 0;
            for expr in input_expressions.iter() {
                input_degree = std::cmp::max(input_degree, expr.degree());
            }

            input_degree
        };

        let inputs_expressions_degree: usize = self
            .inputs_expressions
            .iter()
            .map(|input_expressions| expr_degree(input_expressions))
            .sum();

        let mut table_degree = 0;
        for expr in self.table_expressions.iter() {
            table_degree = std::cmp::max(table_degree, expr.degree());
        }

        /*
            φ_i(X) = f_i(X) + α
            τ(X) = t(X) + α
            LHS = τ(X) * Π(φ_i(X)) * (ϕ(gX) - ϕ(X))
                = table_degree + sum(input_degree) + 1
            RHS = τ(X) * Π(φ_i(X)) * (∑ 1/(φ_i(X)) - m(X) / τ(X))))

            deg(q(X)) = (1 - (q_last + q_blind)) * (LHS - RHS)
                 = 1 + LHS
        */

        let lhs_degree = table_degree + inputs_expressions_degree + 1;
        let degree = lhs_degree + 1;

        // 3 = phi + q_blind + table (where table is = 1)
        // + 1 for each of inputs expressions
        std::cmp::max(3 + self.inputs_expressions.len(), degree)
    }

    /// Returns input of this argument
    pub fn input_expressions(&self) -> &Vec<Vec<Expression<F>>> {
        &self.inputs_expressions
    }

    /// Returns table of this argument
    pub fn table_expressions(&self) -> &Vec<Expression<F>> {
        &self.table_expressions
    }
}

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
            q(X) = (1 - (q_last + q_blind))(((t(X) + α) * (f_i(X) + α) * (ϕ(gX) - ϕ(X)) - (t(X) + α) * (f_i + α) * (1/(f_i(X) + α) - m(X) / (t(X) + α))))
                = table_degree + input_degree + 2
        */
        std::cmp::max(4, input_degree + table_degree + 2)
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
