use ff::Field;
use plotters::{
    coord::Shift,
    prelude::{DrawingArea, DrawingAreaErrorKind, DrawingBackend},
};
use std::{cmp, println, collections::HashMap, format};
use std::collections::HashSet;
use std::ops::Range;

use crate::{
    circuit::{layouter::RegionColumn, Value},
    plonk::{
        Advice, Any, Assigned, Assignment, Challenge, Circuit, Column, ConstraintSystem, Error, 
        Fixed, FloorPlanner, Instance, Selector,
    },
};

/// Graphical renderer for circuit layouts.
///
/// Cells that have been assigned to by the circuit will be shaded. If any cells are
/// assigned to more than once (which is usually a mistake), they will be shaded darker
/// than the surrounding cells.
///
/// # Examples
///
/// ```ignore
/// use halo2_proofs::dev::CircuitLayout;
/// use plotters::prelude::*;
///
/// let drawing_area = BitMapBackend::new("example-circuit-layout.png", (1024, 768))
///     .into_drawing_area();
/// drawing_area.fill(&WHITE).unwrap();
/// let drawing_area = drawing_area
///     .titled("Example Circuit Layout", ("sans-serif", 60))
///     .unwrap();
///
/// let circuit = MyCircuit::default();
/// let k = 5; // Suitable size for MyCircuit
/// CircuitLayout::default().render(k, &circuit, &drawing_area).unwrap();
/// ```
#[derive(Debug, Default)]
pub struct CircuitLayout {

    hide_labels: bool,
    show_region_names: bool,
    show_cell_annotations: bool,
    show_cell_assignments: bool,
    show_column_names: bool,
    mark_equality_cells: bool,
    
    show_equality_constraints: bool,
    view_width: Option<Range<usize>>,
    view_height: Option<Range<usize>>,

    target_region_name: Option<String>,
    target_region_idx: Option<usize>,
}

impl CircuitLayout {
    /// Sets the visibility of region labels.
    ///
    /// The default is to show labels.
    pub fn show_labels(mut self, show: bool) -> Self {
        self.hide_labels = !show;
        self
    }

    pub fn show_cell_annotations(mut self, show: bool) -> Self {
        self.show_cell_annotations = show;
        self
    }

    pub fn show_cell_assignments(mut self, show: bool) -> Self {
        self.show_cell_assignments = show;
        self
    }

    pub fn show_column_names(mut self, show: bool) -> Self {
        self.show_column_names = show;
        self
    }

    pub fn show_region_names(mut self, show: bool) -> Self {
        self.show_region_names = show;
        self
    }

    pub fn regions_by_name(mut self, name: String) -> Self {
        self.target_region_name = Some(name);
        self
    }

    pub fn regions_by_idx(mut self, idx: usize) -> Self {
        self.target_region_idx = Some(idx);
        self
    }

    /// Marks cells involved in equality constraints, in red.
    ///
    /// The default is to not mark these cells.
    pub fn mark_equality_cells(mut self, show: bool) -> Self {
        self.mark_equality_cells = show;
        self
    }

    /// Draws red lines between equality-constrained cells.
    ///
    /// The default is to not show these, as they can get _very_ messy.
    pub fn show_equality_constraints(mut self, show: bool) -> Self {
        self.show_equality_constraints = show;
        self
    }

    /// Sets the view width for this layout, as a number of columns.
    pub fn view_width(mut self, width: Range<usize>) -> Self {
        self.view_width = Some(width);
        self
    }

    /// Sets the view height for this layout, as a number of rows.
    pub fn view_height(mut self, height: Range<usize>) -> Self {
        self.view_height = Some(height);
        self
    }

    // fn draw_and_label_cells(
    //     labels: &mut Vec<(Text<(i32, i32), String>, (usize, usize))>, 
    //     cells: HashMap<(RegionColumn, usize), (Option<String>, Option<Assigned<F>>)>
    // ) {
    //     for ((column, row), (annotation, value)) in cells {
    //         draw_cell(&root, column_index(&cs, column), row).unwrap();
    //         match annotation {
    //             Some(annotation) if self.show_cell_annotations => {
    //                 labels.push((
    //                     Text::new(annotation.clone(), (10, 10), ("sans-serif", 15.0).into_font()),
    //                     (column_index(&cs, column), row))
    //                 );
    //             },
    //             _ => (),
    //         };
    //         match value {
    //             Some(value) if self.show_cell_assignments => {
    //                 labels.push((
    //                     Text::new(format!("{}", value), (10, 10), ("sans-serif", 15.0).into_font()),
    //                     (column_index(&cs, column), row))
    //                 );
    //             },
    //             _ => (),
    //         };
    //     }
    // };


    /// Renders the given circuit on the given drawing area.
    pub fn render<F: Field, ConcreteCircuit: Circuit<F>, DB: DrawingBackend>(
        self,
        k: u32,
        circuit: &ConcreteCircuit,
        drawing_area: &DrawingArea<DB, Shift>,
    ) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
        use plotters::coord::types::RangedCoordusize;
        use plotters::prelude::*;

        let n = 1 << k;
        // Collect the layout details.
        let mut cs = ConstraintSystem::default();
        let config = ConcreteCircuit::configure(&mut cs);
        let mut layout = Layout::new(k, n, cs.num_selectors);
        ConcreteCircuit::FloorPlanner::synthesize(
            &mut layout,
            circuit,
            config,
            cs.constants.clone(),
        )
        .unwrap();

        println!("\nDone synthesize. \n{:?}", layout.regions[0].columns);
    
        let (cs, selector_polys) = cs.compress_selectors(layout.selectors);
        let non_selector_fixed_columns = cs.num_fixed_columns - selector_polys.len();

 
        println!("\nConstraintSystem: total_fixed {:?} = fixed {:?} + selector {:?}, advice {:?}, instance {:?}", 
            cs.num_fixed_columns,
            non_selector_fixed_columns,
            selector_polys.len(),
            cs.num_advice_columns,
            cs.num_instance_columns
        );

        // Figure out what order to render the columns in.
        // TODO: For now, just render them in the order they were configured.
        let total_columns = cs.num_instance_columns + cs.num_advice_columns + cs.num_fixed_columns;
        let column_index = |cs: &ConstraintSystem<F>, column: RegionColumn| {
            let column: Column<Any> = match column {
                RegionColumn::Column(col) => col,
                RegionColumn::Selector(selector) => cs.selector_map[selector.0].into(),
            };
            column.index()
                + match column.column_type() {
                    Any::Instance => 0,
                    Any::Advice(_) => cs.num_instance_columns,
                    Any::Fixed => cs.num_instance_columns + cs.num_advice_columns,
                }
        };

        let view_width = self.view_width.unwrap_or(0..total_columns);
        let view_height = self.view_height.unwrap_or(0..n);
        let view_bottom = view_height.end;

        println!("view_width {:?}, view_height {:?}", 
            view_width, view_height
        );

        // ================================


        // Prepare the grid layout. We render a red background for advice columns, white for
        // instance columns, and blue for fixed columns (with a darker blue for selectors).
        let root =
            drawing_area.apply_coord_spec(Cartesian2d::<RangedCoordusize, RangedCoordusize>::new(
                view_width,
                view_height,
                drawing_area.get_pixel_range(),
            ));

        // All Cols & Rows
        root.draw(&Rectangle::new(
            [(0, 0), (total_columns, view_bottom)],
            ShapeStyle::from(&WHITE).filled(),
        ))?;

        // Advice - Red
        root.draw(&Rectangle::new(
            [
                (cs.num_instance_columns, 0),
                (cs.num_instance_columns + cs.num_advice_columns, view_bottom),
            ],
            ShapeStyle::from(&RED.mix(0.2)).filled(),
        ))?;

        // Fixed - Blue
        root.draw(&Rectangle::new(
            [
                (cs.num_instance_columns + cs.num_advice_columns, 0),
                (
                    cs.num_instance_columns
                        + cs.num_advice_columns
                        + non_selector_fixed_columns,
                    view_bottom,
                ),
            ],
            ShapeStyle::from(&BLUE.mix(0.2)).filled(),
        ))?;
        
        // Selector - Dark Blue
        {
            root.draw(&Rectangle::new(
                [
                    (
                        cs.num_instance_columns
                            + cs.num_advice_columns
                            + non_selector_fixed_columns,
                        0,
                    ),
                    (total_columns, view_bottom),
                ],
                ShapeStyle::from(&YELLOW.mix(0.1)).filled(),
            ))?;
        }

        // Mark the unusable rows of the circuit.
        let usable_rows = n - (cs.blinding_factors() + 1);
        if view_bottom > usable_rows {
            root.draw(&Rectangle::new(
                [(0, usable_rows), (total_columns, view_bottom)],
                ShapeStyle::from(&RED.mix(0.4)).filled(),
            ))?;
        }

        root.draw(&Rectangle::new(
            [(0, 0), (total_columns, view_bottom)],
            &BLACK,
        ))?;

        let draw_region = |root: &DrawingArea<_, _>, top_left, bottom_right| {
            root.draw(&Rectangle::new(
                [top_left, bottom_right],
                ShapeStyle::from(&WHITE).filled(),
            ))?;
            root.draw(&Rectangle::new(
                [top_left, bottom_right],
                ShapeStyle::from(&RED.mix(0.2)).filled(),
            ))?;
            root.draw(&Rectangle::new(
                [top_left, bottom_right],
                ShapeStyle::from(&GREEN.mix(0.2)).filled(),
            ))?;
            root.draw(&Rectangle::new([top_left, bottom_right], &BLACK))?;
            Ok(())
        };
        
        let draw_cell = |root: &DrawingArea<_, _>, column, row| {
            root.draw(&Rectangle::new(
                [(column, row), (column + 1, row + 1)],
                ShapeStyle::from(&BLACK.mix(0.1)).filled(),
            ))
        };

        // Render the regions!
        let mut labels: Vec<(Text<(i32, i32), String>, (usize, usize))> = Vec::new();
        for region in &layout.regions {
            if let Some(offset) = region.offset {
                // Sort the region's columns according to the defined ordering.
                let mut columns = region.columns.keys().cloned().collect::<Vec<_>>();
                columns.sort_unstable_by_key(|a| column_index(&cs, *a));

                // Render contiguous parts of the same region as a single box.
                let mut width = None;
                for column in columns {
                    let idx = column_index(&cs, column);
                    if self.show_column_names {
                        if let Some(name) = region.columns.get(&column).unwrap() {
                            // Columns
                            labels.push((
                                Text::new(name.clone(), (10, 10), ("sans-serif", 15.0).into_font()),
                                (idx, offset))
                            );
                        }
                    }
                    match width {
                        Some((start, end)) if end == idx => width = Some((start, end + 1)),
                        Some((start, end)) => {
                            draw_region(&root, (start, offset), (end, offset + region.rows))?;
                            if self.show_region_names {
                                labels.push((
                                    Text::new(region.name.clone(), (10, 10), ("sans-serif", 15.0).into_font()),
                                    (start, offset))
                                );
                            }
                            width = Some((idx, idx + 1));
                        }
                        None => width = Some((idx, idx + 1)),
                    }
                }

                // Render the last part of the region.
                if let Some((start, end)) = width {
                    draw_region(&root, (start, offset), (end, offset + region.rows))?;
                    if self.show_column_names {
                        labels.push((
                            Text::new(region.name.clone(), (10, 10), ("sans-serif", 15.0).into_font()),
                            (start, offset))
                        );
                    }
                }
            }
        }

        let draw_and_label_cells = 
            | labels: &mut Vec<(Text<(i32, i32), String>, (usize, usize))>, cells: HashMap<(RegionColumn, usize), (Option<String>, Option<Assigned<F>>)>| 
            {
                for ((column, row), (annotation, value)) in cells {
                    draw_cell(&root, column_index(&cs, column), row).unwrap();
                    match annotation {
                        Some(annotation) if self.show_cell_annotations => {
                            labels.push((
                                Text::new(annotation.clone(), (10, 10), ("sans-serif", 15.0).into_font()),
                                (column_index(&cs, column), row))
                            );
                        },
                        _ => (),
                    };
                    match value {
                        Some(value) if self.show_cell_assignments => {
                            labels.push((
                                Text::new(format!("{}", value), (10, 10), ("sans-serif", 15.0).into_font()),
                                (column_index(&cs, column), row))
                            );
                        },
                        _ => (),
                    };
                }
            };

        // Darken the cells of the region that have been assigned to.
        for region in layout.regions {
            draw_and_label_cells(&mut labels, region.cells)
        }
        draw_and_label_cells(&mut labels, layout.loose_cells);


        // Mark equality-constrained cells.
        if self.mark_equality_cells {
            let mut cells = HashSet::new();
            for (l_col, l_row, r_col, r_row) in &layout.equality {
                let l_col = column_index(&cs, (*l_col).into());
                let r_col = column_index(&cs, (*r_col).into());

                // Deduplicate cells.
                cells.insert((l_col, *l_row));
                cells.insert((r_col, *r_row));
            }

            for (col, row) in cells {
                root.draw(&Rectangle::new(
                    [(col, row), (col + 1, row + 1)],
                    ShapeStyle::from(&RED.mix(0.5)).filled(),
                ))?;
            }
        }

        // Draw lines between equality-constrained cells.
        if self.show_equality_constraints {
            for (l_col, l_row, r_col, r_row) in &layout.equality {
                let l_col = column_index(&cs, (*l_col).into());
                let r_col = column_index(&cs, (*r_col).into());
                root.draw(&PathElement::new(
                    [(l_col, *l_row), (r_col, *r_row)],
                    ShapeStyle::from(&RED),
                ))?;
            }
        }

        // Add a line showing the total used rows.
        root.draw(&PathElement::new(
            [(0, layout.total_rows), (total_columns, layout.total_rows)],
            ShapeStyle::from(&BLACK),
        ))?;

        root.draw_mesh(
            |b, l| {
                l.draw(b, &ShapeStyle::from(&BLACK.mix(0.2)).filled())
            }, 
            n, 
            total_columns
        )?;


        // Render labels last, on top of everything else.
        if !self.hide_labels {
            for (label, top_left) in labels {
                root.draw(&(EmptyElement::at(top_left) + label))?;
            }
            root.draw(
                &(EmptyElement::at((0, layout.total_rows))
                    + Text::new(
                        format!("{} used rows", layout.total_rows),
                        (10, 10),
                        ("sans-serif", 15.0).into_font(),
                    )),
            )?;
            root.draw(
                &(EmptyElement::at((0, usable_rows))
                    + Text::new(
                        format!("{} usable rows", usable_rows),
                        (10, 10),
                        ("sans-serif", 15.0).into_font(),
                    )),
            )?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Region<AF> {
    /// The name of the region. Not required to be unique.
    name: String,
    /// The columns used by this region.
    columns: HashMap<RegionColumn, Option<String>>,
    /// The row that this region starts on, if known.
    offset: Option<usize>,
    /// The number of rows that this region takes up.
    rows: usize,
    /// The cells assigned in this region. We store this as a `Vec` so that if any cells
    /// are double-assigned, they will be visibly darker.
    cells: HashMap<(RegionColumn, usize), (Option<String>, Option<AF>)>,
}

#[derive(Default)]
struct Layout<AF> {
    k: u32,
    regions: Vec<Region<AF>>,
    current_region: Option<usize>,
    total_rows: usize,
    /// Any cells assigned outside of a region. We store this as a `Vec` so that if any
    /// cells are double-assigned, they will be visibly darker.
    loose_cells: HashMap<(RegionColumn, usize), (Option<String>, Option<AF>)>,
    /// Pairs of cells between which we have equality constraints.
    equality: Vec<(Column<Any>, usize, Column<Any>, usize)>,
    /// Selector assignments used for optimization pass
    selectors: Vec<Vec<bool>>,
}


impl<AF> Layout<AF> {
    fn new(k: u32, n: usize, num_selectors: usize) -> Self {
        Layout {
            k,
            regions: vec![],
            current_region: None,
            total_rows: 0,
            /// Any cells assigned outside of a region. We store this as a `Vec` so that if any
            /// cells are double-assigned, they will be visibly darker.
            loose_cells: HashMap::new(),
            /// Pairs of cells between which we have equality constraints.
            equality: vec![],
            /// Selector assignments used for optimization pass
            selectors: vec![vec![false; n]; num_selectors],
        }
    }

    fn get_regions_by_name(&self, name: &str) -> Vec<usize> {
        self.regions.iter()
            .enumerate()
            .filter(|(i, r)| r.name == name)
            .map(|(i, r)| i)
            .collect()
    }

    fn get_region_by_idx(&self, idx: usize) -> Option<&Region<AF>> {
        self.regions.get(idx)
    }

    fn has_column(&self, column: RegionColumn) -> bool {
        if let Some(region) = self.current_region {
            self.regions[region].columns.contains_key(&column)
        } else {
            false
        }
    }

    fn update_column(&mut self, column: RegionColumn, annotation: Option<String>) {
        if let Some(region) = self.current_region {
            let region = &mut self.regions[region];
            region.columns.insert(column, annotation);
        }
    }

    fn update_cell(&mut self, column: RegionColumn, row: usize, annotation: Option<String>, value: Option<AF>) {
        self.total_rows = cmp::max(self.total_rows, row + 1);

        if let Some(region) = self.current_region {
            let region = &mut self.regions[region];
            // The region offset is the earliest row assigned to.
            let mut offset = region.offset.unwrap_or(row);
            if row < offset {
                // The first row assigned was not at offset 0 within the region.
                region.rows += offset - row;
                offset = row;
            }
            // The number of rows in this region is the gap between the earliest and
            // latest rows assigned.
            region.rows = cmp::max(region.rows, row - offset + 1);
            region.offset = Some(offset);
            region.cells.insert((column, row), (annotation, value));
        } else {
            self.loose_cells.insert((column, row), (annotation, value));
        }
    }

}

impl<F: Field> Assignment<F> for Layout<Assigned<F>> {
    fn enter_region<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        assert!(self.current_region.is_none());
        self.current_region = Some(self.regions.len());
        self.regions.push(Region {
            name: name_fn().into(),
            columns: HashMap::default(),
            offset: None,
            rows: 0,
            cells: HashMap::default(),
        })
    }

    fn exit_region(&mut self) {
        assert!(self.current_region.is_some());
        self.current_region = None;
    }

    fn enable_selector<A, AR>(&mut self, annotation: A, selector: &Selector, row: usize) -> Result<(), Error>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        if let Some(cell) = self.selectors[selector.0].get_mut(row) {
            *cell = true;
        } else {
            return Err(Error::not_enough_rows_available(self.k));
        }
        Ok(())
    }

    fn query_instance(&self, _: Column<Instance>, _: usize) -> Result<Value<F>, Error> {
        Ok(Value::unknown())
    }

    fn assign_advice<V, VR, A, AR>(
        &mut self,
        annotation: A,
        column: Column<Advice>,
        row: usize,
        to: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<F>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let mut value = Assigned::Zero;
        to().map(|t| value = t.into());
        let column = RegionColumn::from(Column::<Any>::from(column));
        
        if !self.has_column(column) {
            self.update_column(column, None);
        }
        self.update_cell(column, row, Some(annotation().into()), Some(value));
        Ok(())
    }

    fn assign_fixed<V, VR, A, AR>(
        &mut self,
        annotation: A,
        column: Column<Fixed>,
        row: usize,
        to: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<F>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let mut value = Assigned::Zero;
        to().map(|t| value = t.into());
        let column = RegionColumn::from(Column::<Any>::from(column));
        
        if !self.has_column(column) {
            self.update_column(column, None);
        }
        self.update_cell(column, row, Some(annotation().into()), Some(value));
        Ok(())
    }

    fn copy(
        &mut self,
        l_col: Column<Any>,
        l_row: usize,
        r_col: Column<Any>,
        r_row: usize,
    ) -> Result<(), crate::plonk::Error> {
        self.equality.push((l_col, l_row, r_col, r_row));
        Ok(())
    }

    fn fill_from_row(
        &mut self,
        _: Column<Fixed>,
        _: usize,
        _: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn get_challenge(&self, _: Challenge) -> Value<F> {
        Value::unknown()
    }

    fn annotate_column<A, AR>(&mut self, annotation: A, mut column: Column<Any>)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.update_column(
            RegionColumn::from(Column::<Any>::from(column)),
            Some(annotation().into())
        );
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self, _: Option<String>) {
        // Do nothing; we don't care about namespaces in this context.
    }
}
