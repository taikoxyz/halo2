use ff::Field;
use plotters::{
    coord::Shift,
    prelude::{DrawingArea, DrawingAreaErrorKind, DrawingBackend},
};
use sha3::digest::generic_array::typenum::SquareRoot;
use core::panic;
use std::{cmp, println, collections::HashMap, format, fmt::{Debug, self}};
use std::collections::HashSet;
use std::ops::Range;

use crate::{
    circuit::{layouter::RegionColumn, Value},
    plonk::{
        Advice, Any, Assigned, Assignment, Challenge, Circuit, Column, ConstraintSystem, Error, 
        Fixed, FloorPlanner, Instance, Selector,
    },
};

use plotters::coord::types::RangedCoordusize;
use plotters::prelude::*;

/// Todo: 
///     - Fix selector annotation
///     - Coordinate with CellManager

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
pub struct CircuitLayout<DB: DrawingBackend, F: Field> {

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

    root: Option<DrawingArea<DB, Cartesian2d::<RangedCoordusize, RangedCoordusize>>>,
    cs: Option<ConstraintSystem<F>>,
}

impl<DB: DrawingBackend, F: Field> Default for CircuitLayout<DB, F> {
    fn default() -> Self {
        Self {
            hide_labels: false,
            show_region_names: true,
            show_cell_annotations: false,
            show_cell_assignments: false,
            show_column_names: false,
            mark_equality_cells: false,
            show_equality_constraints: false,
            view_width: None,
            view_height: None,
            target_region_name: None,
            target_region_idx: None,
            root: None,
            cs: None,
        }
    }
}

impl<DB: DrawingBackend, F: Field> Debug for CircuitLayout<DB, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CircuitLayout")
            .field("view_width", &self.view_width)
            .field("view_height", &self.view_height)
            .field("target_region_name", &self.target_region_name)
            .field("target_region_idx", &self.target_region_idx)
            .finish()
    }
}

impl<DB: DrawingBackend, F: Field> CircuitLayout<DB, F> {
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

    pub fn region_by_name(mut self, name: &str) -> Self {
        self.target_region_name = Some(name.to_string());
        self
    }

    pub fn region_by_idx(mut self, idx: usize) -> Self {
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

    fn apply_drawing_area(
        &mut self, 
        drawing_area: &DrawingArea<DB, Shift>,
        width: Range<usize>, 
        height: Range<usize>
    ) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
        match (self.view_width.as_ref(), self.view_height.as_ref()) {
            (Some(w), Some(h)) => {
                self.root = Some(drawing_area
                    .apply_coord_spec(Cartesian2d::<RangedCoordusize, RangedCoordusize>::new(
                        w.clone(),
                        h.clone(),
                        drawing_area.get_pixel_range(),
                    ))
                );
            },
            (Some(w), None) => {
                self.view_height = Some(height.clone());
                self.root = Some(drawing_area
                    .apply_coord_spec(Cartesian2d::<RangedCoordusize, RangedCoordusize>::new(
                        w.clone(),
                        height,
                        drawing_area.get_pixel_range(),
                    ))
                );
            },
            (None, Some(h)) => {
                self.view_width = Some(width.clone());
                self.root = Some(drawing_area
                    .apply_coord_spec(Cartesian2d::<RangedCoordusize, RangedCoordusize>::new(
                        width,
                        h.clone(),
                        drawing_area.get_pixel_range(),
                    ))
                );
            },
            (None, None) => {
                self.view_width = Some(width.clone());
                self.view_height = Some(height.clone());
                self.root = Some(drawing_area
                    .apply_coord_spec(Cartesian2d::<RangedCoordusize, RangedCoordusize>::new(
                        width,
                        height,
                        drawing_area.get_pixel_range(),
                    ))
                );
            },
        };
        Ok(())
    }

    fn draw_mesh(&self) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>>{
        // Draw mesh grid for all rows and columns
        self.root.as_ref()
            .expect("Root not set")
            .draw_mesh(
                |b, l| {
                    l.draw(b, &ShapeStyle::from(&BLACK.mix(0.2)).filled())
                }, 
                self.view_height.as_ref().unwrap().end, 
                self.view_width.as_ref().unwrap().end
            )?;
        Ok(())
    }

    fn column_index(&self, column: &RegionColumn) -> usize {
        if let Some(cs) = &self.cs {
            let column = match column {
                RegionColumn::Column(col) => col.clone(),
                RegionColumn::Selector(selector) => cs.selector_map[selector.0].into(),
            };
            column.index()
                + match column.column_type() {
                    Any::Instance => 0,
                    Any::Advice(_) => cs.num_instance_columns,
                    Any::Fixed => cs.num_instance_columns + cs.num_advice_columns,
                }
        } else {
            panic!("Constraint system not set")
        }
    }

    fn draw_and_label_cells(
        &self,
        cells: &HashMap<(RegionColumn, usize), (Option<String>, Option<Assigned<F>>)>
    )  -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
        let mut labels: Vec<(Text<(i32, i32), String>, (usize, usize))> = Vec::new();
        for ((column, row), (annotation, value)) in cells {
            let row = row.clone();
            let col_idx = self.column_index(column);
            if let Some(root) = &self.root {
                root.draw(&Rectangle::new(
                    [(col_idx, row), (col_idx + 1, row + 1)],
                    ShapeStyle::from(&BLACK.mix(0.1)).filled(),
                ))?;
            }
            match annotation {
                Some(annotation) if self.show_cell_annotations => {
                    labels.push((
                        Text::new(annotation.clone(), (1, 1), ("sans-serif", 15.0).into_font()),
                        (col_idx, row))
                    );
                },
                _ => (),
            };
            match value {
                Some(value) if self.show_cell_assignments => {
                    labels.push((
                        Text::new(format!("{:?}", value), (1, 1), ("sans-serif", 15.0).into_font()),
                        (col_idx, row))
                    );
                },
                _ => (),
            };
        }
        self.draw_labels(labels)?;
        Ok(())
    }
    

    fn region_area(&self, region: &Region<Assigned<F>>) -> (Range<usize>, Range<usize>) {
        let start = self.column_index(region.columns.keys().collect::<Vec<_>>()[0]);
        let (left, right) = region.columns.iter()
            .fold((start, start + 1), |(start, end), (c, _)| 
                {
                    let c_idx = self.column_index(c);
                    (
                        cmp::min(start, c_idx),
                        cmp::max(end, c_idx + 1)
                    )
                }
            );
        (left..right, region.offset.unwrap_or(0)..region.rows)
    }

    fn draw_region(
        &self,
        region: &Region<Assigned<F>>
    ) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
        let mut labels = Vec::new();

        let draw_region = |top_left:(usize, usize), buttom_right: (usize, usize)| {
            if let Some(root) = &self.root {
                // root.draw(&Rectangle::new(
                //     [top_left, buttom_right],
                //     ShapeStyle::from(&WHITE).filled(),
                // ))?;
                // root.draw(&Rectangle::new(
                //     [top_left, buttom_right],
                //     ShapeStyle::from(&RED.mix(0.2)).filled(),
                // ))?;
                root.draw(&Rectangle::new(
                    [top_left, buttom_right],
                    ShapeStyle::from(&GREEN.mix(0.1)).filled(),
                ))?;
                root.draw(&Rectangle::new([top_left, buttom_right], &BLACK))?;

            } else {
                panic!("No root set");
            }
            Ok(())
        };
        let offset = region.offset.unwrap_or(0);
        // Sort the region's columns according to the defined ordering.
        let mut columns = region.columns.keys().cloned().collect::<Vec<_>>();
        columns.sort_unstable_by_key(|a| self.column_index(a));

        // Render contiguous parts of the same region as a single box.
        let mut width = None;
        for column in columns {
            let idx: usize = self.column_index(&column);
            if self.show_column_names {
                if let Some(name) = region.columns.get(&column).unwrap() {
                    // Columns
                    labels.push((
                        Text::new(name.clone(), (1, 1), ("sans-serif", 15.0).into_font()),
                        (idx, offset))
                    );
                }
            }
            match width {
                Some((start, end)) if end == idx => width = Some((start, end + 1)),
                Some((start, end)) => {
                    draw_region( (start, offset), (end, offset + region.rows))?;
                    if self.show_region_names {
                        labels.push((
                            Text::new(region.name.clone(), (1, 1), ("sans-serif", 15.0).into_font()),
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
            draw_region((start, offset), (end, offset + region.rows))?;
            if self.show_column_names {
                labels.push((
                    Text::new(region.name.clone(), (1, 1), ("sans-serif", 15.0).into_font()),
                    (start, offset))
                );
            }
        }
        self.draw_and_label_cells(&region.cells)?;
        self.draw_labels(labels)?;
        Ok(())
    }

    fn draw_labels(
        &self, 
        labels: Vec<(Text<(i32, i32), String>, (usize, usize))>
    ) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
        // Render labels last, on top of everything else.
        if !self.hide_labels {
            for (label, top_left) in labels {
                self.root.as_ref().unwrap().draw(&(EmptyElement::at(top_left) + label))?;
            }
        }
        Ok(())
    }

    fn draw_circuit(
        &self, 
        layout: Layout<Assigned<F>>,
        column_ranges: (usize, usize, usize, usize),
    ) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {

        let view_bottom = self.view_height.as_ref().unwrap().end;
        let total_columns = self.view_width.as_ref().unwrap().end;

        if let Some(root) = &self.root {
            // All Cols & Rows
            root.draw(&Rectangle::new(
                [(0, 0), (total_columns, view_bottom)],
                ShapeStyle::from(&WHITE).filled(),
            ))?;
            // Advice - Red
            root.draw(&Rectangle::new(
                [
                    (column_ranges.0, 0),
                    (column_ranges.1, view_bottom),
                ],
                ShapeStyle::from(&RED.mix(0.2)).filled(),
            ))?;
            // Fixed - Blue
            root.draw(&Rectangle::new(
                [
                    (column_ranges.1, 0),
                    (column_ranges.2, view_bottom)
                ],
                ShapeStyle::from(&BLUE.mix(0.2)).filled(),
            ))?;
            // Selector - Dark Blue
            {
                root.draw(&Rectangle::new(
                    [
                        (column_ranges.2, 0),
                        (column_ranges.3, view_bottom),
                    ],
                    ShapeStyle::from(&YELLOW.mix(0.1)).filled(),
                ))?;
            }
            let usable_rows = view_bottom - (self.cs.as_ref().unwrap().blinding_factors() + 1);
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
            
            // Render the regions!
            for region in &layout.regions {
                self.draw_region(region)?;
            }

            // Darken the cells of the region that have been assigned to.
            for region in layout.regions {
                self.draw_and_label_cells(&region.cells)?;
            }
            self.draw_and_label_cells(&layout.loose_cells)?;


            // Mark equality-constrained cells.
            if self.mark_equality_cells {
                let mut cells = HashSet::new();
                for (l_col, l_row, r_col, r_row) in &layout.equality {
                    let l_col = self.column_index(&(*l_col).into());
                    let r_col = self.column_index(&(*r_col).into());

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
                    let l_col = self.column_index(&(*l_col).into());
                    let r_col = self.column_index(&(*r_col).into());
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

            // Render labels last, on top of everything else.
            if !self.hide_labels {
                root.draw(
                    &(EmptyElement::at((0, layout.total_rows))
                        + Text::new(
                            format!("{} used rows", layout.total_rows),
                            (1, 1),
                            ("sans-serif", 15.0).into_font(),
                        )),
                )?;
                root.draw(
                    &(EmptyElement::at((0, usable_rows))
                        + Text::new(
                            format!("{} usable rows", usable_rows),
                            (1, 1),
                            ("sans-serif", 15.0).into_font(),
                        )),
                )?;
            }
        }
        Ok(())
    }

    /// Renders the given circuit on the given drawing area.
    pub fn render<ConcreteCircuit: Circuit<F>>(
        mut self,
        k: u32,
        circuit: &ConcreteCircuit,
        drawing_area: &DrawingArea<DB, Shift>,
    ) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {

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

        println!("\nDone synthesize! \n{:?}", layout.regions[0].columns);
    
        let (cs, selector_polys) = cs.compress_selectors(layout.selectors.clone());
        self.cs = Some(cs.clone());

        // ================================

        // Draw specific region

        
        if let Some(r) = self.target_region_idx {
            let region = layout.regions
                .get(r)
                .expect("region does not exists");
            let (width, height) = self.region_area(region);
            self.apply_drawing_area(drawing_area, width, height);
            self.draw_region(region)?;
            self.draw_mesh()?;
            return Ok(());
        } 
        if let Some(s) = &self.target_region_name {
            let r = layout.get_regions_by_name(s).expect("region does not exists");
            let region = &layout.regions[r];
            let (width, height) = self.region_area(region);
            self.apply_drawing_area(drawing_area, width, height);
            self.draw_region(region)?;
            self.draw_mesh()?;
            return Ok(());
        }

        // ================================
        // Figure out what order to render the columns in.
        // TODO: For now, just render them in the order they were configured.

        let total_columns = cs.num_instance_columns + cs.num_advice_columns + cs.num_fixed_columns;
        self.apply_drawing_area(drawing_area, 0..total_columns, 0..n);
        
        self.draw_circuit(
            layout, 
            (
                cs.num_instance_columns, 
                cs.num_instance_columns + cs.num_advice_columns, 
                cs.num_instance_columns + cs.num_advice_columns + cs.num_fixed_columns - selector_polys.len(),
                total_columns
            )
        )?;
        self.draw_mesh()?;
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

    fn get_regions_by_name(&self, name: &str) -> Option<usize> {
        self.regions.iter()
            .position(|r| r.name == name)
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

    // Thoughts: 之后做Cell Label，通过 A: FnOnce() -> AR
    // 传一个 struct CellInfo = (CellType, String)进来，
    // CellInfo实现AR：Into<String> 把名字留下，CellType 拿去 render
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

    fn annotate_column<A, AR>(&mut self, annotation: A, column: Column<Any>)
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
